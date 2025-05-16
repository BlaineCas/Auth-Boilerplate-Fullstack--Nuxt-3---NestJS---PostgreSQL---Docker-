import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name); // Logger for this service

  constructor(
    // Injects the TypeORM repository for the User entity
    @InjectRepository(User)
    public readonly userRepository: Repository<User>, // Public to be accessible directly in AuthService for specific queries
  ) {}

  // Creates a new user
  async create(createUserDto: Partial<User>): Promise<User> {
    const newUser = this.userRepository.create(createUserDto);
    this.logger.log(`Creating new user with email: ${newUser.email}`);
    return this.userRepository.save(newUser);
  }

  // Finds a user by email
  async findByEmail(email: string): Promise<User | null> {
    this.logger.debug(`Finding user by email: ${email}`);
    return this.userRepository.findOne({ where: { email } });
  }

  // Finds a user by Google ID
  async findByGoogleId(googleId: string): Promise<User | null> {
    this.logger.debug(`Finding user by Google ID: ${googleId}`);
    return this.userRepository.findOne({ where: { googleId } });
  }

  // Finds a user by ID
  async findById(id: string): Promise<User | null> {
    this.logger.debug(`Finding user by ID: ${id}`);
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      this.logger.warn(`User with ID "${id}" not found`);
      // Do not throw NotFoundException here, let the calling service decide
    }
    return user;
  }

  // Finds or creates a user based on OAuth data (e.g., Google)
  async findOrCreateByOAuth(
    email: string,
    googleId: string,
    firstName?: string,
    lastName?: string,
    avatarUrl?: string,
  ): Promise<User> {
    this.logger.log(
      `Attempting to find or create user via OAuth for email: ${email}, googleId: ${googleId}`,
    );
    let user = await this.findByGoogleId(googleId);
    if (user) {
      this.logger.log(
        `User found by Google ID: ${googleId}. Updating details if necessary.`,
      );
      // Update the details if they have changed in Google
      user.firstName = firstName !== undefined ? firstName : user.firstName;
      user.lastName = lastName !== undefined ? lastName : user.lastName;
      user.avatarUrl = avatarUrl !== undefined ? avatarUrl : user.avatarUrl;
      if (!user.email && email) user.email = email; // Ensure the email is set
      user.isEmailVerified = true; // The email is considered verified via Google
      return this.userRepository.save(user);
    }

    // If no user is found by googleId, check if an account exists with that email
    user = await this.findByEmail(email);
    if (user) {
      this.logger.log(
        `User found by email: ${email}. Linking Google ID: ${googleId}.`,
      );
      // The user already exists with this email, but does not have a googleId set. We link it.
      user.googleId = googleId;
      user.firstName = firstName !== undefined ? firstName : user.firstName;
      user.lastName = lastName !== undefined ? lastName : user.lastName;
      user.avatarUrl = avatarUrl !== undefined ? avatarUrl : user.avatarUrl;
      user.isEmailVerified = true; // The email is verified via Google
      return this.userRepository.save(user);
    }

    // Otherwise, create a new user
    this.logger.log(
      `No existing user found. Creating new user for email: ${email}, googleId: ${googleId}.`,
    );
    const newUser = this.userRepository.create({
      email,
      googleId,
      firstName,
      lastName,
      avatarUrl,
      isEmailVerified: true, // The email is considered verified via Google
      role: UserRole.USER,
    });
    return this.userRepository.save(newUser);
  }

  // Sets the token and expiration date for email verification
  async setEmailVerificationToken(
    userId: string,
    token: string | null,
    expires: Date | null,
  ): Promise<void> {
    this.logger.log(`Setting email verification token for user ID: ${userId}`);
    await this.userRepository.update(userId, {
      emailVerificationToken: token,
      emailVerificationExpires: expires,
    });
  }

  // Finds a user by email verification token
  async findByEmailVerificationToken(token: string): Promise<User | null> {
    this.logger.debug(`Finding user by email verification token.`);
    return this.userRepository.findOne({
      where: {
        emailVerificationToken: token,
      },
    });
  }

  // Marks the email as verified and deletes the token
  async verifyEmail(userId: string): Promise<void> {
    this.logger.log(`Verifying email for user ID: ${userId}`);
    await this.userRepository.update(userId, {
      isEmailVerified: true,
      emailVerificationToken: null,
      emailVerificationExpires: null,
    });
  }

  // Sets the token and expiration date for password reset
  async setPasswordResetToken(
    userId: string,
    token: string | null,
    expires: Date | null,
  ): Promise<void> {
    this.logger.log(`Setting password reset token for user ID: ${userId}`);
    await this.userRepository.update(userId, {
      passwordResetToken: token,
      passwordResetExpires: expires,
    });
  }

  // Finds a user by password reset token
  async findByPasswordResetToken(token: string): Promise<User | null> {
    this.logger.debug(`Finding user by password reset token.`);
    return this.userRepository.findOne({
      where: {
        passwordResetToken: token,
      },
    });
  }

  // Updates the user's password and deletes the reset token
  async updateUserPassword(
    userId: string,
    newPasswordHash: string,
  ): Promise<void> {
    this.logger.log(`Updating password for user ID: ${userId}`);
    await this.userRepository.update(userId, {
      password: newPasswordHash,
      passwordResetToken: null,
      passwordResetExpires: null,
    });
  }
}
