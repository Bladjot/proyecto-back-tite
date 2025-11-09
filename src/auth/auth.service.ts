// ✅ src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
  private recaptchaSecret: string;
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.recaptchaSecret = this.configService.get<string>(
      'RECAPTCHA_V2_SECRET_KEY',
    );
  }
  private async validateRecaptcha(token: string): Promise<boolean> {
    if (!this.recaptchaSecret) {
      console.warn('RECAPTCHA_V2_SECRET_KEY no está configurada. Omitiendo validación.');
      // En desarrollo, podrías permitir que pase si la clave no está.
      // En producción, deberías lanzar un error.
      // throw new InternalServerErrorException('reCAPTCHA no configurado');
      return true; // Omitir si no hay clave
    }

    const verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          `${verifyUrl}?secret=${this.recaptchaSecret}&response=${token}`,
        ),
      );
      
      return response.data.success === true;

    } catch (error) {
      console.error('Error al validar reCAPTCHA:', error.message);
      return false;
    }
  }
  /**
   * Determina la ruta destino después del login según el rol.
   */
  private resolvePostLoginRedirect(roles?: string[]): string {
    if (!Array.isArray(roles)) {
      return '/dashboard';
    }

    const normalizedRoles = roles
      .filter((role): role is string => typeof role === 'string')
      .map((role) => role.toLowerCase());
    if (normalizedRoles.includes('admin')) {
      return '/admin';
    }

    return '/dashboard';
  }

  /**
   * 🔐 Validar credenciales de usuario (login tradicional)
   */
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      const plainUser = user.toObject ? user.toObject() : user;
      delete plainUser.password;
      return plainUser;
    }
    return null;
  }

  /**
   * 🔑 Login normal con email y contraseña
   */
  async login(loginDto: LoginDto) {
    const isRecaptchaValid = await this.validateRecaptcha(loginDto.recaptchaToken);
    if (!isRecaptchaValid) {
      throw new BadRequestException('Falló la verificación de reCAPTCHA');
    }
    const user = await this.validateUser(loginDto.email, loginDto.password);
    const payload = {
      email: user.email,
      sub: user._id?.toString(),
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
      rut: user.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(user.roles);

    return {
      user: {
        id: user._id?.toString(),
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        rut: user.rut,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
        foto: user.foto ?? null,
      },
      access_token: this.jwtService.sign(payload),
      redirectTo,
    };
  }

  /**
   * 🧾 Registro de usuario nuevo
   */
  async register(registerDto: RegisterDto) {
    const isRecaptchaValid = await this.validateRecaptcha(registerDto.recaptchaToken);
    if (!isRecaptchaValid) {
      throw new BadRequestException('Falló la verificación de reCAPTCHA');
    }
    const existing = await this.usersService.findByEmail(registerDto.email);
    const hashed = await bcrypt.hash(registerDto.password, 10);

    const createUserDto: CreateUserDto = {
      name: registerDto.name,
      lastName: registerDto.lastName,
      rut: registerDto.rut,
      email: registerDto.email,
      password: hashed,
      roles: ['cliente'],
      permisos: [],
      isActive: true,
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;

    const payload = {
      email: user.email,
      sub: user._id?.toString(),
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
      rut: user.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(user.roles);

    return {
      user: {
        id: user._id?.toString(),
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        rut: user.rut,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
        foto: user.foto ?? null,
      },
      access_token: this.jwtService.sign(payload),
      redirectTo,
    };
  }

  /**
   * 👤 Obtener datos del usuario autenticado
   */
  async me(userId: string) {
    return this.usersService.findOne(userId);
  }

  /**
   * Obtener detalles del perfil (biografía + preferencias)
   */
  async getProfileDetails(userId: string) {
    return this.usersService.findProfileDetails(userId);
  }

  /**
   * Actualizar nombre, apellido, biografía, foto y/o preferencias
   */
  async updateProfileDetails(
    userId: string,
    dto: {
      name?: string;
      lastName?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      email?: string;
      telefono?: string;
      currentPassword?: string;
      newPassword?: string;
    },
  ) {
    const user = await this.usersService.findByIdWithPassword(userId);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const updatePayload: {
      name?: string;
      lastName?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      telefono?: string | null;
      email?: string;
      passwordHash?: string;
    } = {
      name: dto.name,
      lastName: dto.lastName,
      biografia: dto.biografia,
      foto: dto.foto,
      preferencias: dto.preferencias,
    };

    if (typeof dto.telefono !== 'undefined') {
      updatePayload.telefono = dto.telefono ?? null;
    }

    if (typeof dto.email !== 'undefined' && dto.email !== user.email) {
      const emailTaken = await this.usersService.findByEmail(dto.email);
      if (emailTaken && emailTaken._id?.toString() !== user._id?.toString()) {
        throw new ConflictException('El correo ya está registrado por otro usuario.');
      }
      updatePayload.email = dto.email;
    }

    if (dto.newPassword) {
      if (!dto.currentPassword) {
        throw new BadRequestException(
          'Debes incluir la contraseña actual para cambiarla.',
        );
      }
      const isCurrentPasswordValid = await bcrypt.compare(
        dto.currentPassword,
        user.password,
      );
      if (!isCurrentPasswordValid) {
        throw new BadRequestException('La contraseña actual no es correcta.');
      }
      updatePayload.passwordHash = await bcrypt.hash(dto.newPassword, 10);
    }

    return this.usersService.updateProfileDetails(userId, updatePayload);
  }

  /**
   * ✅ Verificar si el usuario puede acceder a una página
   */
  async canAccessPage(userId: string, page: string): Promise<boolean> {
    const userDocument = await this.usersService.findOne(userId);
    const user =
      userDocument && userDocument.toObject
        ? userDocument.toObject()
        : (userDocument as any);

    const permisos: string[] = Array.isArray(user.permisos)
      ? user.permisos
      : [];

    return permisos.some(
      (permiso) => permiso.toLowerCase() === page.toLowerCase(),
    );
  }

  /**
   * 🔑 Login con Google OAuth
   */
  async googleLogin(googleUser: any) {
    if (!googleUser) {
      throw new UnauthorizedException('Error en autenticación con Google');
    }

    let user = await this.usersService.findByEmail(googleUser.email);

    // Crear si no existe
    if (!user) {
      const inferredRut =
        googleUser.rut ||
        googleUser?.profile?.rut ||
        googleUser?.profile?.rutNumber ||
        googleUser?.rutNumber;

      if (!inferredRut) {
        throw new BadRequestException(
          'No se pudo obtener el RUT desde la cuenta de Google. Completa tu registro manualmente.',
        );
      }

      const createUserDto: CreateUserDto = {
        name: googleUser.firstName || 'Google',
        lastName: googleUser.lastName || 'User',
        rut: inferredRut,
        email: googleUser.email,
        password: await bcrypt.hash('google-auth', 10),
        roles: ['cliente'],
        permisos: [],
        isActive: true,
      };
      user = await this.usersService.create(createUserDto);
    }

    const plainUser = user.toObject ? user.toObject() : user;
    const userId = plainUser._id?.toString();

    const payload = {
      email: plainUser.email,
      sub: userId,
      roles: plainUser.roles || ['cliente'],
      permisos: plainUser.permisos || [],
      rut: plainUser.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(plainUser.roles);

    return {
      user: {
        id: userId,
        email: plainUser.email,
        name: plainUser.name,
        lastName: plainUser.lastName,
        rut: plainUser.rut,
        roles: plainUser.roles || ['cliente'],
        permisos: plainUser.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
      redirectTo,
    };
  }

  /**
   * 🔍 Verifica si un correo existe
   */
  async checkEmail(email: string) {
    const user = await this.usersService.findByEmail(email);
    return !!user;
  }

  /**
   * 🔍 Buscar usuario por email (para AuthController)
   */
  async findByEmail(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new NotFoundException('Usuario no encontrado');
    return user;
  }

  /**
   * 🔐 Actualizar contraseña del usuario
   */
  async updatePassword(email: string, newPassword: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();

    return { message: 'Contraseña actualizada correctamente' };
  }
}
