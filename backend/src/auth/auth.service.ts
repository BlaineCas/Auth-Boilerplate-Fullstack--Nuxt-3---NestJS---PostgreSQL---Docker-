import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  Logger,
  ForbiddenException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { RegisterUserDto } from './dto/register-user.dto';
import { User, UserRole } from '../users/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { randomBytes, createHash } from 'crypto';
import { JwtPayload } from './strategies/jwt.strategy';

export interface RefreshTokenPayload {
  sub: string;
  tokenId?: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly CLIENT_URL: string;
  private readonly JWT_ACCESS_SECRET: string;
  private readonly JWT_ACCESS_EXPIRES_IN: string;
  private readonly JWT_REFRESH_SECRET: string;
  private readonly JWT_REFRESH_EXPIRES_IN: string;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.CLIENT_URL = this.configService.get<string>('CLIENT_URL') as string;
    this.JWT_ACCESS_SECRET = this.configService.get<string>(
      'JWT_SECRET',
    ) as string;
    this.JWT_ACCESS_EXPIRES_IN = this.configService.get<string>(
      'JWT_EXPIRES_IN',
    ) as string;
    this.JWT_REFRESH_SECRET = this.configService.get<string>(
      'JWT_REFRESH_SECRET',
    ) as string;
    this.JWT_REFRESH_EXPIRES_IN = this.configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
    ) as string;
  }

  private generateAccessToken(user: Partial<User>): string {
    const payload: JwtPayload = {
      sub: user.id as string,
      email: user.email as string,
      role: user.role as string,
      firstName: user.firstName as string,
      lastName: user.lastName as string,
      avatarUrl: user.avatarUrl as string,
      isEmailVerified: user.isEmailVerified as boolean,
    };
    this.logger.debug(`Generating Access Token for user ID: ${user.id}`);
    return this.jwtService.sign(payload, {
      secret: this.JWT_ACCESS_SECRET,
      expiresIn: this.JWT_ACCESS_EXPIRES_IN,
    });
  }

  private generateRefreshToken(user: Partial<User>): {
    token: string;
    tokenId: string;
    expiresAt: Date;
  } {
    const tokenId = randomBytes(16).toString('hex');
    const payload: RefreshTokenPayload = {
      sub: user.id as string,
      tokenId,
    };

    const expiresInSeconds = this.parseExpiry(this.JWT_REFRESH_EXPIRES_IN);
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

    const token = this.jwtService.sign(payload, {
      secret: this.JWT_REFRESH_SECRET,
      expiresIn: this.JWT_REFRESH_EXPIRES_IN,
    });

    return { token, tokenId, expiresAt };
  }

  private parseExpiry(expiryString: string): number {
    const unit = expiryString.charAt(expiryString.length - 1);
    const value = parseInt(expiryString.slice(0, -1), 10);
    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 60 * 60 * 24;
      default:
        throw new Error('Invalid expiry unit');
    }
  }

  private async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  private async compareHash(
    data: string,
    hashedData: string,
  ): Promise<boolean> {
    return bcrypt.compare(data, hashedData);
  }

  private async updateRefreshToken(
    userId: string,
    refreshToken: string,
    tokenId: string,
    expiresAt: Date,
  ): Promise<void> {
    this.logger.log(`Updating refreshToken for user ID: ${userId}`);

    const hashedRefreshToken = await this.hashData(refreshToken);

    await this.usersService.userRepository.update(userId, {
      hashedRefreshToken: hashedRefreshToken,
      refreshTokenId: tokenId,
      refreshTokenExpiresAt: expiresAt,
    });
    this.logger.log(`Updated refreshTokenId for user ID: ${userId}`);
  }

  private async generateAndStoreTokens(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const accessToken = this.generateAccessToken(user);
    const {
      token: refreshToken,
      tokenId,
      expiresAt: refreshTokenExpiresAt,
    } = this.generateRefreshToken(user);

    await this.updateRefreshToken(
      user.id,
      refreshToken,
      tokenId,
      refreshTokenExpiresAt,
    );

    return { accessToken, refreshToken };
  }

  async register(registerUserDto: RegisterUserDto): Promise<{
    accessToken: string;
    refreshToken: string;
    user: Partial<User>;
  }> {
    const { email, password, firstName, lastName } = registerUserDto;
    this.logger.log(`Registration attempt for email: ${email}`);

    const existingUser = await this.usersService.findByEmail(email);
    if (existingUser) {
      this.logger.warn(`Registration failed: email ${email} already exists.`);
      throw new BadRequestException(
        'Un utilizator cu acest email există deja.',
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      // const verificationToken = this.generateRandomToken();
      // const verificationExpires = new Date(Date.now() + 24 * 3600000);

      const userToCreateData: Partial<User> = {
        email,
        password: hashedPassword,
        firstName,
        lastName,
        role: UserRole.USER,
        isEmailVerified: false,
        // emailVerificationToken: this.hashToken(verificationToken),
        // emailVerificationExpires: verificationExpires,
      };

      const newUser = await this.usersService.create(userToCreateData);
      this.logger.log(
        `User ${email} registered successfully with ID: ${newUser.id}.`,
      );

      // const verificationUrl = `${this.CLIENT_URL}/auth/verify-email?token=${verificationToken}`;
      // this.logger.log(`Verification URL (dev only): ${verificationUrl}`);
      // try { await this.mailService.sendUserConfirmation(newUser, verificationUrl); } catch (e) { /* ... */ }

      const { accessToken, refreshToken } =
        await this.generateAndStoreTokens(newUser);

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const {
        password: _,
        emailVerificationToken: __,
        passwordResetToken: ___,
        hashedRefreshToken: ____,
        refreshTokenExpiresAt: _____,
        ...userResult
      } = newUser;
      return { accessToken, refreshToken, user: userResult };
    } catch (error) {
      this.logger.error(
        `Failed to register user ${email}. Error: ${error.message}`,
        error.stack,
      );
      if (error.code === '23505') {
        throw new BadRequestException('This email is already in use.');
      }
      throw new InternalServerErrorException(
        'An error occurred while registering the user.',
      );
    }
  }

  async login(user: User): Promise<{
    accessToken: string;
    refreshToken: string;
    user: Partial<User>;
  }> {
    this.logger.log(
      `Login successful for user ID: ${user.id}, email: ${user.email}`,
    );

    const { accessToken, refreshToken } =
      await this.generateAndStoreTokens(user);
    await this.usersService.userRepository.update(user.id, {
      lastLoginAt: new Date(),
    });

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {
      password,
      emailVerificationToken,
      passwordResetToken,
      hashedRefreshToken,
      refreshTokenExpiresAt,
      ...userResult
    } = user;
    return { accessToken, refreshToken, user: userResult };
  }

  async googleLogin(reqUser: any): Promise<{
    accessToken: string;
    refreshToken: string;
    user: Partial<User>;
  }> {
    this.logger.log(
      `Google login attempt for user: ${JSON.stringify(reqUser.email)}`,
    );
    if (!reqUser || !reqUser.email || !reqUser.googleId) {
      this.logger.error(
        'Google login failed: incomplete data from Google profile.',
      );
      throw new BadRequestException(
        'Datele Google incomplete nu au putut fi procesate.',
      );
    }
    const { email, googleId, firstName, lastName, avatarUrl } = reqUser;

    try {
      const user = await this.usersService.findOrCreateByOAuth(
        email,
        googleId,
        firstName,
        lastName,
        avatarUrl,
      );
      this.logger.log(
        `User ${user.email} (ID: ${user.id}) processed via Google OAuth.`,
      );

      const { accessToken, refreshToken } =
        await this.generateAndStoreTokens(user);
      await this.usersService.userRepository.update(user.id, {
        lastLoginAt: new Date(),
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const {
        password,
        emailVerificationToken,
        passwordResetToken,
        hashedRefreshToken: _,
        refreshTokenExpiresAt: __,
        ...userResult
      } = user;
      return { accessToken, refreshToken, user: userResult };
    } catch (error) {
      this.logger.error(
        `Google login failed for ${email}. Error: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Autentificarea Google a eșuat.');
    }
  }

  async refreshToken(
    providedToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    let payload: RefreshTokenPayload;

    try {
      payload = this.jwtService.verify(providedToken, {
        secret: this.JWT_REFRESH_SECRET,
      }) as RefreshTokenPayload;
    } catch (err) {
      throw new ForbiddenException('Invalid refresh token.');
    }

    const user = await this.usersService.findById(payload.sub);
    if (
      !user ||
      !user.refreshTokenId ||
      user.refreshTokenId !== payload.tokenId
    ) {
      throw new ForbiddenException('Refresh token is no longer valid.');
    }

    if (user.refreshTokenExpiresAt && user.refreshTokenExpiresAt < new Date()) {
      throw new ForbiddenException('Refresh token has expired.');
    }

    if (user.hashedRefreshToken) {
      const comparedHash = await this.compareHash(
        providedToken,
        user.hashedRefreshToken,
      );
      if (!comparedHash) {
        throw new ForbiddenException('Refresh token is no longer valid.');
      }
    }

    const { accessToken, refreshToken } =
      await this.generateAndStoreTokens(user);

    return { accessToken, refreshToken };
  }

  async logout(userId: string): Promise<{ message: string }> {
    this.logger.log(`Logout attempt for user ID: ${userId}`);
    // Invalidate refresh token
    await this.usersService.userRepository.update(userId, {
      hashedRefreshToken: null,
      refreshTokenExpiresAt: null,
      refreshTokenId: null,
    });
    this.logger.log(
      `User ID: ${userId} logged out successfully. Refresh token invalidated.`,
    );
    return { message: 'Deconectare reușită.' };
  }

  async validateUser(email: string, pass: string): Promise<User | null> {
    // Returnează User complet pentru a-l pasa la login
    this.logger.debug(`Attempting to validate user: ${email}`);
    const userWithPassword = await this.usersService.userRepository
      .createQueryBuilder('user')
      .addSelect('user.password')
      .addSelect('user.isEmailVerified')
      .where('user.email = :email', { email })
      .getOne();

    if (
      userWithPassword &&
      userWithPassword.password &&
      (await bcrypt.compare(pass, userWithPassword.password))
    ) {
      this.logger.log(`User ${email} validated successfully.`);
      return userWithPassword;
    }
    this.logger.warn(
      `Validation failed for user: ${email}. Invalid credentials.`,
    );
    return null;
  }

  private generateRandomTokenUtil(length: number = 32): string {
    return randomBytes(length).toString('hex');
  }

  private hashTokenUtil(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async verifyEmail(token: string): Promise<{
    message: string;
    user?: Partial<User>;
    accessToken?: string;
    refreshToken?: string;
  }> {
    this.logger.log(`Attempting to verify email with token.`);
    const hashedToken = this.hashTokenUtil(token); // Folosim utilitarul redenumit
    const user =
      await this.usersService.findByEmailVerificationToken(hashedToken);

    if (!user) {
      this.logger.warn(
        `Email verification failed: invalid or non-existent token.`,
      );
      throw new BadRequestException('The verification token is invalid.');
    }

    if (
      user.emailVerificationExpires &&
      user.emailVerificationExpires.getTime() < Date.now()
    ) {
      this.logger.warn(
        `Email verification failed for user ${user.email}: token expired.`,
      );
      await this.usersService.setEmailVerificationToken(user.id, null, null);
      throw new BadRequestException('The verification token has expired.');
    }

    await this.usersService.verifyEmail(user.id);
    this.logger.log(
      `Email verified successfully for user ${user.email} (ID: ${user.id}).`,
    );

    //  (isEmailVerified = true)
    const updatedUser = await this.usersService.findById(user.id);
    if (!updatedUser)
      throw new InternalServerErrorException(
        'The user was not found after email verification.',
      );

    const { accessToken, refreshToken } =
      await this.generateAndStoreTokens(updatedUser);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {
      password,
      emailVerificationToken,
      passwordResetToken,
      hashedRefreshToken: _,
      refreshTokenExpiresAt: __,
      ...userResult
    } = updatedUser;

    return {
      message: 'Email verificat cu succes!',
      user: userResult,
      accessToken,
      refreshToken,
    };
  }

  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    this.logger.log(`Attempting to resend verification email to: ${email}`);
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      this.logger.warn(
        `Resend verification attempt for non-existing email: ${email}`,
      );
      return {
        message:
          'If an account with this email exists, a new verification email has been sent.',
      };
    }

    if (user.isEmailVerified) {
      this.logger.warn(
        `Resend verification attempt for already verified email: ${email}`,
      );
      throw new BadRequestException('The email is already verified.');
    }

    const verificationToken = this.generateRandomTokenUtil();
    const verificationExpires = new Date(Date.now() + 24 * 3600000);

    await this.usersService.setEmailVerificationToken(
      user.id,
      this.hashTokenUtil(verificationToken),
      verificationExpires,
    );
    this.logger.log(`New verification token set for user ${email}.`);

    const verificationUrl = `${this.CLIENT_URL}/auth/verify-email?token=${verificationToken}`;
    this.logger.log(`Resend Verification URL (dev only): ${verificationUrl}`);
    // try { await this.mailService.sendUserConfirmation(user, verificationUrl); } catch (e) { /* ... */ }

    return { message: 'A new verification email has been sent.' };
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    this.logger.log(`Forgot password attempt for email: ${email}`);
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      this.logger.warn(
        `Forgot password attempt for non-existing email: ${email}`,
      );
      return {
        message:
          'If an account with this email exists, a password reset email has been sent.',
      };
    }

    const resetToken = this.generateRandomTokenUtil();
    const resetExpires = new Date(Date.now() + 1 * 3600000);

    await this.usersService.setPasswordResetToken(
      user.id,
      this.hashTokenUtil(resetToken),
      resetExpires,
    );
    this.logger.log(`Password reset token set for user ${email}.`);

    const resetUrl = `${this.CLIENT_URL}/auth/reset-password?token=${resetToken}`;
    this.logger.log(`Password Reset URL (dev only): ${resetUrl}`);
    // try { await this.mailService.sendPasswordReset(user, resetUrl); } catch (e) { /* ... */ }
    return {
      message:
        'If an account with this email exists, a password reset email has been sent.',
    };
  }

  async resetPassword(
    token: string,
    newPasswordPlain: string,
  ): Promise<{ message: string }> {
    this.logger.log(`Attempting to reset password with token.`);
    const hashedToken = this.hashTokenUtil(token); // Folosim utilitarul redenumit
    const user = await this.usersService.findByPasswordResetToken(hashedToken);

    if (!user) {
      this.logger.warn(`Password reset failed: invalid or non-existent token.`);
      throw new BadRequestException('The reset token is invalid.');
    }
    if (
      user.passwordResetExpires &&
      user.passwordResetExpires.getTime() < Date.now()
    ) {
      this.logger.warn(
        `Password reset failed for user ${user.email}: token expired.`,
      );
      await this.usersService.setPasswordResetToken(user.id, null, null);
      throw new BadRequestException('The reset token has expired.');
    }

    const newHashedPassword = await bcrypt.hash(newPasswordPlain, 10);
    await this.usersService.updateUserPassword(user.id, newHashedPassword);
    await this.usersService.userRepository.update(user.id, {
      hashedRefreshToken: null,
      refreshTokenExpiresAt: null,
      refreshTokenId: null,
    });

    this.logger.log(
      `Password reset successfully for user ${user.email} (ID: ${user.id}).`,
    );
    return { message: 'The password has been reset.' };
  }
}
