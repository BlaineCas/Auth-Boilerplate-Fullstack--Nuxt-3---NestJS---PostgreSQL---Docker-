import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { User } from './users/entities/user.entity'; // Import the User entity
import { LogLevel } from 'typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes the ConfigModule globally available throughout the app
      envFilePath: '.env', // Specifies the path to the .env file
      // ignoreEnvFile: process.env.NODE_ENV === 'production', // Optional: ignore .env in production if variables are set differently
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule], // Import ConfigModule to be able to inject ConfigService
      useFactory: (configService: ConfigService) => {
        const logger = new Logger('TypeOrmConfig');
        const dbConfig = {
          type: 'postgres' as const, // Specifies the database type
          host: configService.get<string>('DB_HOST') as string,
          port: parseInt(configService.get<string>('DB_PORT') as string, 10),
          username: configService.get<string>('DB_USERNAME') as string,
          password: configService.get<string>('DB_PASSWORD'),
          database: configService.get<string>('DB_DATABASE'),
          entities: [
            User, // Add the User entity here
            // Add other entities as you create them
          ],
          // `synchronize: true` is useful for development (automatically creates tables),
          // BUT IT MUST BE `false` IN PRODUCTION to avoid data loss.
          // In production, use TypeORM migrations.
          synchronize: configService.get<string>('NODE_ENV') === 'development',
          logging:
            (configService.get<string>('NODE_ENV') as string) === 'development'
              ? (['query', 'error'] as LogLevel[])
              : (['error'] as LogLevel[]),
        };
        logger.log(
          `Connecting to database: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database} as ${dbConfig.username}`,
        );
        if (dbConfig.synchronize) {
          logger.warn(
            'TypeORM synchronize is ENABLED. Database schema will be updated automatically. Disable for production.',
          );
        }
        return dbConfig;
      },
      inject: [ConfigService], // Inject ConfigService into useFactory
    }),
    UsersModule, // Import the Users module
    AuthModule, // Import the Auth module
  ],
})
export class AppModule {}
