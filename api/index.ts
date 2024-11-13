// functions/index.ts
import { onRequest } from 'firebase-functions/v2/https';
import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import proxy from '@fastify/http-proxy';
import compress from '@fastify/compress';
import zlib, { BrotliDecompress, Gunzip, Inflate } from 'zlib';
import { IncomingMessage, ServerResponse } from 'http';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { ManagementClient, AuthenticationClient, UserInfoClient } from 'auth0';
import { logger } from 'firebase-functions/v2';

const CONFIG = {
  API: 'aignx-orion-api 0.0.6',
  DICOMWEB_ORIGIN_BASE_URL: 'https://healthcare.googleapis.com',
  DICOMWEB_PREFIX: '/api/dicomweb',
  REGION: 'europe-west4',
  MEMORY: '1GiB',
  TIMEOUT_SECONDS: 540,
  MAX_RESPONSE_SIZE: 900 * 1024 * 1024,
  MAX_CONCURRENT: 100,
  MAX_INSTANCES: 10,
  MIN_INSTANCES: 0,
} as const;

const AUTH_CONFIG = {
  AUTH0_DOMAIN: process.env.AUTH0_DOMAIN || 'dev-4af67kto0u7aachc.eu.auth0.com',
  AUTH0_AUDIENCE: process.env.AUTH0_AUDIENCE || 'https://orion.aignostics.com/api',
  AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID || '2rhsBivqpRSe59kGTO3vNGhxvOG9O2pb',
  GOOGLE_PROJECT_NUMBER: process.env.GOOGLE_PROJECT_NUMBER || '409698935820',
  GOOGLE_WORKLOAD_POOL: process.env.GOOGLE_WORKLOAD_POOL || 'auth0-identity-pool',
  GOOGLE_PROVIDER_ID: process.env.GOOGLE_PROVIDER_ID || 'auth0-provider',
} as const;

const CONTENT_TYPES_URL_REPLACE = [
  'bapplication/json',
  'bapplication/dicom+json',
];

const CONTENT_TYPES_ERROR_REPLACE = [
  'text/html',
  'application/text'
];

type Decompressor = BrotliDecompress | Gunzip | Inflate | undefined;

const auth0UserInfoClient = new UserInfoClient({
  domain: AUTH_CONFIG.AUTH0_DOMAIN
});

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// JWT verification setup for Auth0
const verifyAuth0Token = jwksClient({
  jwksUri: `https://${AUTH_CONFIG.AUTH0_DOMAIN}/.well-known/jwks.json`,
  cache: true,
  rateLimit: true,
});

// exchange token, see https://medium.com/google-cloud/gcp-workload-identity-federation-with-federated-tokens-d03b8bad0228
async function exchangeAuth0WithGoogleToken(auth0Token: string): Promise<string> {
  try {
    logger.debug('Exchanging token:', auth0Token);

    const response = await fetch('https://sts.googleapis.com/v1/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
        audience: `//iam.googleapis.com/projects/${AUTH_CONFIG.GOOGLE_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${AUTH_CONFIG.GOOGLE_WORKLOAD_POOL}/providers/${AUTH_CONFIG.GOOGLE_PROVIDER_ID}`,
        scope: 'https://www.googleapis.com/auth/cloud-healthcare',
        requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        subjectToken: auth0Token,
        subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt'
      })
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.statusText}`);
    }

    const data = await response.json();
    if (!data.access_token) {
      throw new Error('No access token in response');
    }

    logger.debug('Token got in exchange:', data.access_token);
    return data.access_token;
 
  } catch (error) {
    logger.error('Error exchanging token:', error);
    throw error;
  }
}

// Function to check if token is a Google OAuth2 access token
async function isGoogleOAuth2Token(token: string): Promise<boolean> {
  try {
    // Try to use the token to access Google's tokeninfo endpoint
    const response = await fetch(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${token}`);
    if (!response.ok) {
      logger.debug('Not a Google Token:', response.statusText);
      return false;
    }
    const data = await response.json();
    
    // Check if the token has the necessary scope
    const rtn = data.scope?.includes('https://www.googleapis.com/auth/cloud-healthcare');
    if (!rtn) {
      logger.error('Google token does not have required scope:', data.scope);
    }
    return rtn;
  } catch (error) {
    logger.error('Failed to check Google token:', error);
    return false;
  }
}

// Auth middleware
async function verifyToken(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization;
    logger.debug('Auth header:', authHeader);
    if (!authHeader?.startsWith('Bearer ')) {
      throw new Error('No token provided');
    }

    const accessToken = authHeader.split(' ')[1];
    logger.debug('Access Token:', accessToken);

    // First check if it's a Google OAuth2 access token
    if (await isGoogleOAuth2Token(accessToken)) {
      logger.debug('Using provided Google OAuth2 token directly');
      // Keep the existing Google token
      return;
    }

    const decodedToken: any = jwt.decode(accessToken, { complete: true });
    
    if (!decodedToken) {
      throw new Error('Invalid token!');
    }

    logger.debug('Decoded token:', decodedToken);

    // Verify token signature and claims
    const key = await verifyAuth0Token.getSigningKey(decodedToken.header.kid);
    logger.debug('Key:', key);
    const signingKey = key.getPublicKey();
    logger.debug('Signing key:', signingKey);

    const verified: any = await new Promise((resolve, reject) => {
      jwt.verify(
        accessToken,
        signingKey,
        {
          audience: AUTH_CONFIG.AUTH0_AUDIENCE,
          issuer: `https://${AUTH_CONFIG.AUTH0_DOMAIN}/`,
          algorithms: ['RS256'],
        },
        (err, decoded) => {
          if (err) reject(err);
          resolve(decoded);
        }
      );
    });

    logger.debug('Verified token:', verified);

    // Get Google token and update request
    const googleToken = await exchangeAuth0WithGoogleToken(accessToken);
    request.headers.auth0AccessToken = accessToken;
    request.headers.authorization = `Bearer ${googleToken}`;

  } catch (error) {
    request.log.error(error, 'Token verification failed');
    reply.code(401).send({ 
      error: 'Unauthorized', 
      message: error instanceof Error ? error.message : 'Unknown error' 
    });
    throw error;
  }
}

async function getUserProfile(request: FastifyRequest) {
  try {
    const accessToken = request.headers.auth0AccessToken;
    if (!accessToken || Array.isArray(accessToken)) {
      throw Error("No valid Auth0 access token found in request");
    }
    logger.debug('Access Token:', accessToken);
    return await auth0UserInfoClient.getUserInfo(accessToken);
  } catch (error) {
    logger.error(error)
    throw new Error(`Failed to fetch user info: ${error}`);
  }
}

const app: FastifyInstance = fastify({
  logger: true,
});

app.register(cors);
app.register(compress, { global: false });

// Add authentication middleware
app.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
  if (
    request.url.startsWith(CONFIG.DICOMWEB_PREFIX)
    || request.url == '/api/auth-test'
  ) {
    await verifyToken(request, reply);
  }
});

app.addHook('onResponse', async (request, reply) => {
  const token = request.headers.authorization?.split(' ')[1];
  
  const logInfo = {
    path: request.url,
    method: request.method,
    statusCode: reply.statusCode,
    timestamp: new Date().toISOString()
  };

  if (!token) {
    request.log.debug({
      ...logInfo,
      authStatus: 'no_token'
    }, 'API Access Log');
    return;
  }

  try {
    const decodedToken: any = jwt.decode(token, { complete: true });
    
    if (!decodedToken) {
      request.log.debug({
        ...logInfo,
        authStatus: 'invalid_token_format'
      }, 'API Access Log');
      return;
    }

    // Add token-specific info
    request.log.debug({
      ...logInfo,
      authStatus: 'token_present',
      user: decodedToken?.payload?.sub || 'unknown',
      issuer: decodedToken?.payload?.iss || 'unknown',
      tokenType: decodedToken?.payload?.iss?.includes('googleapis.com') ? 'google' : 'auth0',
      roles: decodedToken?.payload?.['https://healthcare-api/roles'],
    }, 'API Access Log');

  } catch (error) {
    request.log.debug({
      ...logInfo,
      authStatus: 'token_decode_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 'API Access Log');
  }
});

app.register(proxy, {
  prefix: CONFIG.DICOMWEB_PREFIX,
  upstream: CONFIG.DICOMWEB_ORIGIN_BASE_URL,
  rewritePrefix: '',
  disableRequestLogging: false,
  cacheURLs: 1000,
  // contentTypesToEncode: [ 'application/json' ],
  contentTypesToEncode: [ ],
  // retryMethods: ['GET', 'HEAD', 'OPTIONS', 'TRACE'],
  retryMethods: [ ],
  // maxRetriesOn503: 10,
  maxRetriesOn503: 0,
  /*
  http: {
    agentOptions: {
      keepAliveMsecs: 10 * 60 * 1000,
    },
    requestOptions: {
      timeout: 10 * 60 * 1000
    }
  },
  */
  undici: {
    connections: 128,
    pipelining: 10,
    keepAliveTimeout: 10 * 60 * 1000,
  },
  http2: {
    sessionTimeout: 10 * 60 * 1000, // HTTP/2 session timeout in msecs, defaults to 60000 (1 minute)
    requestTimeout: 10 * 60 * 1000, // HTTP/2 request timeout in msecs, defaults to 10000 (10 seconds)
    sessionOptions: { // HTTP/2 session connect options, pass in any options from https://nodejs.org/api/http2.html#http2_http2_connect_authority_options_listener
      rejectUnauthorized: true
    },
    requestOptions: { // HTTP/2 request options, pass in any options from https://nodejs.org/api/http2.html#clienthttp2sessionrequestheaders-options
      endStream: true
    }
  },
  replyOptions: {
    rewriteRequestHeaders: (originalReq: any, headers: any) => ({
      ...headers,
      'x-aignx-api': CONFIG.API,
    }),
    rewriteHeaders: (headers: any) => ({
      ...headers,
      'x-aignx-api': CONFIG.API,
    }),
    onResponse: (request: any, reply: any, response: any) => {
      const contentType = response.headers['content-type'] as string | undefined;
      const requestUrl = request.url as string | undefined;

      if (requestUrl?.endsWith('metadata') && contentType) {
        if (CONTENT_TYPES_URL_REPLACE.some((ct) => contentType.includes(ct))) {
          const protocol =
            (request.headers['x-forwarded-proto'] as string | undefined) ||
            (request.protocol as string | undefined) ||
            'https';
          const forwardedHost = request.headers['x-forwarded-host'] as string | undefined;
          const host = forwardedHost || request.headers.host;

          const apiHost = `${protocol}://${host}`;
          const replacementUrl = `${apiHost}${CONFIG.DICOMWEB_PREFIX}`;

          change_body(request, reply, response, (body: string) => {
            const escapedOriginUrl = escapeRegExp(CONFIG.DICOMWEB_ORIGIN_BASE_URL);
            const regex = new RegExp(escapedOriginUrl, 'g');
            return body.replace(regex, replacementUrl);
          });
        } else if (CONTENT_TYPES_ERROR_REPLACE.some((ct) => contentType.includes(ct))) {
          change_body(request, reply, response, (body: string) => {
            return body.replace('/error/g', 'wonder');
          });
        } else {
          reply.send(response.stream);
        }
      } else {
        reply.send(response.stream);
      }
    },
  },
});

function change_body(
  request: FastifyRequest,
  reply: FastifyReply,
  response: any,
  call_back: (body: string) => string
) {
  const headers = response.headers;
  const contentEncoding = headers['content-encoding'] as string | undefined;

  let decompress: Decompressor;

  switch (contentEncoding) {
    case 'gzip':
      decompress = zlib.createGunzip();
      break;
    case 'br':
      decompress = zlib.createBrotliDecompress();
      break;
    case 'deflate':
      decompress = zlib.createInflate();
      break;
    default:
      decompress = undefined;
  }

  if (decompress) {
    response.stream.pipe(decompress);
    let buffer = Buffer.from('', 'utf8');

    decompress.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
    });

    decompress.on('end', async () => {
      let body = buffer.toString();
      if (body) {
        reply.removeHeader('content-length');
        body = call_back(body);
      }
      reply.compress(body);
    });
  } else {
    let buffer = Buffer.from('', 'utf8');
    response.stream.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
    });
    response.stream.on('end', () => {
      let body = buffer.toString();
      if (body) {
        reply.removeHeader('content-length');
        body = call_back(body);
      }
      reply.send(body);  
    });
  }
}

app.get('/api/health', async (request: FastifyRequest, reply: FastifyReply) => {
  reply.send({ health: 'Ok' });
});

// Test auth endpoint
app.get('/api/auth-test', async (request: FastifyRequest, reply: FastifyReply) => {
  // reply.send({ message: 'Authenticated' });
  reply.send(await getUserProfile(request));
});

const ready = app.ready();

const handler = async (request: IncomingMessage, reply: ServerResponse) => {
  await ready;
  app.server.emit('request', request, reply);
};

exports.api = onRequest(
  {
    invoker: 'public',
    cors: true,
    region: CONFIG.REGION,
    memory: CONFIG.MEMORY,
    timeoutSeconds: CONFIG.TIMEOUT_SECONDS,
    minInstances: CONFIG.MIN_INSTANCES,
    maxInstances: CONFIG.MAX_INSTANCES,
    concurrency: CONFIG.MAX_CONCURRENT,
  },
  handler
);