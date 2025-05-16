import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { User } from '../../users/entities/user.entity';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(LocalStrategy.name);

  constructor(private readonly authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, pass: string): Promise<User> {
    // AuthService.validateUser now returns a complete User
    this.logger.debug(`LocalStrategy validating user: ${email}`);
    const user = (await this.authService.validateUser(email, pass)) as User;
    if (!user) {
      this.logger.warn(
        `LocalStrategy validation failed for ${email}: Invalid credentials.`,
      );
      throw new UnauthorizedException('Invalid credentials.');
    }
    if (!user.isEmailVerified) {
      this.logger.warn(
        `LocalStrategy validation failed for ${email}: Email not verified.`,
      );
      throw new UnauthorizedException(
        'Email address not verified. Please check your inbox.',
      );
    }
    this.logger.log(`LocalStrategy validation successful for ${email}.`);
    return user; // Return the complete User object to be used in AuthService.login
  }
}
