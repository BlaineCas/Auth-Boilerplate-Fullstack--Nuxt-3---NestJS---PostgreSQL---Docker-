import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

// Enum for user roles
export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

@Entity('users') // The table name in the database will be 'users'
export class User {
  @PrimaryGeneratedColumn('uuid') // Primary key automatically generated as UUID
  id: string;

  @Column({ type: 'varchar', length: 255, nullable: true }) // User's first name, optional
  firstName: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true }) // User's last name, optional
  lastName: string | null;

  @Index({ unique: true }) // Unique index for the email column
  @Column({ type: 'varchar', length: 255, unique: true }) // Email address, unique and mandatory
  email: string;

  @Column({ type: 'varchar', length: 255, nullable: true, select: false }) // Hashed password, optional (for OAuth), not selected by default
  password?: string | null;

  @Column({
    type: 'varchar',
    length: 255,
    nullable: true,
    name: 'google_id', // Unique Google ID
    unique: true, // Ensures uniqueness for googleId
  })
  googleId?: string | null;

  @Column({ type: 'varchar', length: 2048, nullable: true, name: 'avatar_url' }) // Avatar URL, optional
  avatarUrl?: string | null;

  @Column({
    type: 'enum',
    enum: UserRole, // The column type is enum, using the UserRole defined above
    default: UserRole.USER, // The default role is 'user'
  })
  role: UserRole;

  @Column({ type: 'boolean', default: false, name: 'is_email_verified' }) // Indicator if the email has been verified
  isEmailVerified: boolean;

  @Column({
    type: 'varchar',
    nullable: true,
    name: 'email_verification_token',
    select: false,
  }) // Token for email verification, not selected by default
  emailVerificationToken?: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
    name: 'email_verification_expires',
    select: false,
  }) // Expiration date of the verification token, not selected by default
  emailVerificationExpires?: Date | null;

  @Column({
    type: 'varchar',
    nullable: true,
    name: 'password_reset_token',
    select: false,
  }) // Token for password reset, not selected by default
  passwordResetToken?: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
    name: 'password_reset_expires',
    select: false,
  }) // Expiration date of the reset token, not selected by default
  passwordResetExpires?: Date | null;

  // Fields for Refresh Token
  @Column({
    type: 'varchar',
    nullable: true,
    name: 'hashed_refresh_token',
    select: false,
  })
  hashedRefreshToken?: string | null;

  @Column({ type: 'varchar', nullable: true })
  refreshTokenId: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
    name: 'refresh_token_expires_at',
    select: false,
  })
  refreshTokenExpiresAt?: Date | null;

  @CreateDateColumn({ name: 'created_at' }) // Record creation date, automatically managed by TypeORM
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' }) // Last update date, automatically managed by TypeORM
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true, name: 'last_login_at' }) // Last login date, optional
  lastLoginAt?: Date | null;

  // Optional constructor to facilitate instance creation
  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
