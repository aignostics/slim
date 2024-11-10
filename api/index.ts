// functions/index.ts
import { onRequest } from 'firebase-functions/v2/https';
import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import proxy from '@fastify/http-proxy';
import compress from '@fastify/compress';
import zlib, { BrotliDecompress, Gunzip, Inflate } from 'zlib';
import { IncomingMessage, ServerResponse } from 'http';

type Decompressor = BrotliDecompress | Gunzip | Inflate | undefined;

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

const CONTENT_TYPES_URL_REPLACE = [
  'bapplication/json',
  'bapplication/dicom+json',
];

const CONTENT_TYPES_ERROR_REPLACE = [
  'text/html',
  'application/text'
];

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const app: FastifyInstance = fastify({
  logger: true,
});

app.register(cors);
app.register(compress, { global: false });
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

app.get('/api/health', async (request, reply) => {
  reply.send({ health: 'Ok' });
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