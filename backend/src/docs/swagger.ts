import path from 'path';
import { Express, Request, Response } from 'express';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const swaggerDefinition = {
  openapi: '3.0.3',
  info: {
    title: 'CryptoVault v2 API',
    version: '2.0.0',
    description: 'Enterprise cryptography API with symmetric, asymmetric, hashing, KDF, JWT/JWE, and ECDH operations.',
  },
  servers: [
    {
      url: '/api/v1',
      description: 'Versioned API base path',
    },
  ],
  components: {
    schemas: {
      ApiResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          data: { nullable: true },
          error: { type: 'string', nullable: true },
          requestId: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
        },
        required: ['success', 'data', 'error', 'requestId', 'timestamp'],
      },
    },
  },
};

const swaggerOptions: swaggerJSDoc.Options = {
  definition: swaggerDefinition,
  apis: [path.resolve(__dirname, '../routes/*.ts')],
};

export const swaggerSpec = swaggerJSDoc(swaggerOptions);

/**
 * @description Mounts Swagger UI and raw OpenAPI JSON endpoints.
 * @algorithm OpenAPI documentation registration
 * @reference OpenAPI 3.0; swagger-ui-express
 * @security Documentation is read-only and contains no sensitive runtime secrets.
 * @param app Express application instance.
 * @returns Void.
 */
export function setupSwagger(app: Express): void {
  app.get('/api/v1/docs.json', (_req: Request, res: Response) => {
    res.status(200).json(swaggerSpec);
  });

  app.use('/api/v1/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}
