// src/main.ts (în proiectul tău NestJS backend)
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    // logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;
  const clientUrl = configService.get<string>('CLIENT_URL');
  const globalPrefix = 'api';

  const logger = new Logger('Bootstrap');

  app.setGlobalPrefix(globalPrefix);

  app.use(cookieParser());
  app.use(helmet());

  // --- START CONFIGURARE CORS ---
  if (clientUrl) {
    logger.log(`CORS enabled for origin: ${clientUrl}`);
    app.enableCors({
      origin: clientUrl,
      methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
      credentials: true,
      allowedHeaders: 'Content-Type, Accept, Authorization',
    });
  } else {
    logger.warn(
      'CLIENT_URL not set in .env. CORS will allow all origins (NOT recommended for production).',
    );
    app.enableCors({
      origin: '*', // Permite orice origine
      methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
      credentials: true,
      allowedHeaders: 'Content-Type, Accept, Authorization',
    });
  }

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  await app.listen(port);
  logger.log(
    `Application is running on: http://localhost:${port}/${globalPrefix}`,
  );
  logger.log(`Client URL (for CORS) set to: ${clientUrl}`);
}
bootstrap();
