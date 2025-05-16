import {
  Controller,
  Get,
  Request,
  UseGuards,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('users') // Defines the base route for this controller as '/users'
export class UsersController {
  private readonly logger = new Logger(UsersController.name); // Logger for this controller

  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard) // Protects this route with the JWT authentication guard
  @Get('profile') // Defines a GET route at '/users/profile'
  async getProfile(@Request() req): Promise<Partial<User>> {
    this.logger.log(`Fetching profile for user ID: ${req.user.id}`);
    // req.user is populated by JwtStrategy with the token payload (which includes the user ID)
    // We search for the user in the database to get the latest data
    const userFromDb = await this.usersService.findById(req.user.id);
    if (!userFromDb) {
      this.logger.warn(
        `User profile requested but user not found in DB: ${req.user.id}`,
      );
      throw new NotFoundException('User not found.');
    }
    // Return the user without the password or other sensitive fields that should not be exposed
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, emailVerificationToken, passwordResetToken, ...result } =
      userFromDb;
    return result;
  }
}
