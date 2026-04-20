import { Router } from 'express';
import asymmetricRouter from './asymmetric.route';
import ecdhRouter from './ecdh.route';
import hashingRouter from './hashing.route';
import healthRouter from './health.route';
import jwtRouter from './jwt.route';
import kdfRouter from './kdf.route';
import symmetricRouter from './symmetric.route';

const apiV1Router = Router();

apiV1Router.use('/symmetric', symmetricRouter);
apiV1Router.use('/asymmetric', asymmetricRouter);
apiV1Router.use('/hash', hashingRouter);
apiV1Router.use('/kdf', kdfRouter);
apiV1Router.use('/jwt', jwtRouter);
apiV1Router.use('/ecdh', ecdhRouter);
apiV1Router.use('/', healthRouter);

export default apiV1Router;
