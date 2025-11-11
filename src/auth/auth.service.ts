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
  async validateUser(correo: string, contrasena: string): Promise<any> {
    const user = await this.usersService.findByCorreo(correo);
    if (user && (await bcrypt.compare(contrasena, user.contrasena))) {
      const plainUser = user.toObject ? user.toObject() : user;
      delete plainUser.contrasena;
      return plainUser;
    }
    return null;
  }

  /**
   * 🔑 Login normal con correo y contraseña
   */
  async login(loginDto: LoginDto) {
    const isRecaptchaValid = await this.validateRecaptcha(loginDto.recaptchaToken);
    if (!isRecaptchaValid) {
      throw new BadRequestException('Falló la verificación de reCAPTCHA');
    }
    const user = await this.validateUser(loginDto.correo, loginDto.contrasena);
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }
    const payload = {
      correo: user.correo,
      sub: user._id?.toString(),
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
      rut: user.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(user.roles);

    return {
      user: {
        id: user._id?.toString(),
        correo: user.correo,
        nombre: user.nombre,
        apellido: user.apellido,
        rut: user.rut,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
        foto: user.foto ?? null,
        activo: user.activo,
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
    const existing = await this.usersService.findByCorreo(registerDto.correo);
    const hashed = await bcrypt.hash(registerDto.contrasena, 10);

    const createUserDto: CreateUserDto = {
      nombre: registerDto.nombre,
      apellido: registerDto.apellido,
      rut: registerDto.rut,
      correo: registerDto.correo,
      contrasena: hashed,
      roles: ['cliente'],
      permisos: [],
      activo: true,
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;

    const payload = {
      correo: user.correo,
      sub: user._id?.toString(),
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
      rut: user.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(user.roles);

    return {
      user: {
        id: user._id?.toString(),
        correo: user.correo,
        nombre: user.nombre,
        apellido: user.apellido,
        rut: user.rut,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
        foto: user.foto ?? null,
        activo: user.activo,
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
      nombre?: string;
      apellido?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      correo?: string;
      telefono?: string;
      contrasenaActual?: string;
      nuevaContrasena?: string;
    },
  ) {
    const user = await this.usersService.findByIdWithPassword(userId);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const updatePayload: {
      nombre?: string;
      apellido?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      telefono?: string | null;
      correo?: string;
      contrasenaHash?: string;
    } = {
      nombre: dto.nombre,
      apellido: dto.apellido,
      biografia: dto.biografia,
      foto: dto.foto,
      preferencias: dto.preferencias,
    };

    if (typeof dto.telefono !== 'undefined') {
      updatePayload.telefono = dto.telefono ?? null;
    }

    if (typeof dto.correo !== 'undefined' && dto.correo !== user.correo) {
      const emailTaken = await this.usersService.findByCorreo(dto.correo);
      if (emailTaken && emailTaken._id?.toString() !== user._id?.toString()) {
        throw new ConflictException('El correo ya está registrado por otro usuario.');
      }
      updatePayload.correo = dto.correo;
    }

    if (dto.nuevaContrasena) {
      if (!dto.contrasenaActual) {
        throw new BadRequestException(
          'Debes incluir la contraseña actual para cambiarla.',
        );
      }
      const isCurrentPasswordValid = await bcrypt.compare(
        dto.contrasenaActual,
        user.contrasena,
      );
      if (!isCurrentPasswordValid) {
        throw new BadRequestException('La contraseña actual no es correcta.');
      }
      updatePayload.contrasenaHash = await bcrypt.hash(dto.nuevaContrasena, 10);
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

    let user = await this.usersService.findByCorreo(googleUser.correo);

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
        nombre: googleUser.nombre || 'Google',
        apellido: googleUser.apellido || 'User',
        rut: inferredRut,
        correo: googleUser.correo,
        contrasena: await bcrypt.hash('google-auth', 10),
        roles: ['cliente'],
        permisos: [],
        activo: true,
      };
      user = await this.usersService.create(createUserDto);
    }

    const plainUser = user.toObject ? user.toObject() : user;
    const userId = plainUser._id?.toString();

    const payload = {
      correo: plainUser.correo,
      sub: userId,
      roles: plainUser.roles || ['cliente'],
      permisos: plainUser.permisos || [],
      rut: plainUser.rut,
    };

    const redirectTo = this.resolvePostLoginRedirect(plainUser.roles);

    return {
      user: {
        id: userId,
        correo: plainUser.correo,
        nombre: plainUser.nombre,
        apellido: plainUser.apellido,
        rut: plainUser.rut,
        roles: plainUser.roles || ['cliente'],
        permisos: plainUser.permisos || [],
        activo: plainUser.activo,
      },
      access_token: this.jwtService.sign(payload),
      redirectTo,
    };
  }

  /**
   * 🔍 Verifica si un correo existe
   */
  async checkCorreo(correo: string) {
    const user = await this.usersService.findByCorreo(correo);
    return !!user;
  }

  /**
   * 🔍 Buscar usuario por correo (para AuthController)
   */
  async findByCorreo(correo: string) {
    const user = await this.usersService.findByCorreo(correo);
    if (!user) throw new NotFoundException('Usuario no encontrado');
    return user;
  }

  /**
   * 🔐 Actualizar contraseña del usuario
   */
  async actualizarContrasena(correo: string, nuevaContrasena: string) {
    const user = await this.usersService.findByCorreo(correo);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const hashed = await bcrypt.hash(nuevaContrasena, 10);
    user.contrasena = hashed;
    await user.save();

    return { message: 'Contraseña actualizada correctamente' };
  }
}
