import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { User } from 'src/users/entities/user.entity';

// Define the JWT payload structure for the Access Token
export interface JwtPayload {
  sub: string; // User ID (subject)
  email: string;
  role: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  isEmailVerified: boolean;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  // Specify the strategy name as 'jwt'
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Important: do NOT ignore expiration for access tokens
      secretOrKey: configService.get<string>('JWT_SECRET') as string, // Use the secret for the Access Token
    });
  }

  // This method validates the payload of an Access Token
  async validate(payload: JwtPayload): Promise<Partial<User>> {
    // Return a partial User object
    this.logger.debug(
      `JwtStrategy (Access Token) validating payload for user ID: ${payload.sub}`,
    );
    const user = await this.usersService.findById(payload.sub); // Check if the user still exists
    if (!user) {
      this.logger.warn(
        `JwtStrategy validation failed: User ID ${payload.sub} not found in DB.`,
      );
      throw new UnauthorizedException(
        'Invalid token or user no longer exists.',
      );
    }

    // It's not necessary to check isEmailVerified here unless a specific route requires it.
    // This can be handled at the controller/service level, or by checking the value here if needed.

    this.logger.log(
      `JwtStrategy validation successful for user ID: ${payload.sub}.`,
    );
    // Return the data that will be available in `req.user`
    return {
      id: payload.sub,
      email: payload.email,
      role: user.role, // It's best to fetch the role from DB to reflect immediate changes
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      isEmailVerified: user.isEmailVerified,
    };
  }
}
