import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]), // Registers the User entity to be used with @InjectRepository
  ],
  providers: [UsersService], // Registers UsersService as a provider in this module
  exports: [UsersService], // Exports UsersService to be used in other modules (e.g., AuthModule)
  controllers: [UsersController], // Registers UsersController
})
export class UsersModule {}
