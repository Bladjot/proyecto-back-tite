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
import { MailService } from '../common/mail/mail.service';

type PasswordResetPayload = {
  token?: string;
  correo?: string;
  nuevaContrasena: string;
};

@Injectable()
export class AuthService {
  private recaptchaSecret: string;
  private readonly frontendBaseUrl: string;
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {
    this.recaptchaSecret = this.configService.get<string>(
      'RECAPTCHA_V2_SECRET_KEY',
    );
    this.frontendBaseUrl =
      this.configService.get<string>('FRONTEND_BASE_URL') ||
      this.configService.get<string>('FRONTEND_URL') ||
      'http://localhost:5173';
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

    // Si no existe, indicamos que debe completar registro y devolvemos datos base
    if (!user) {
      const params = new URLSearchParams();
      params.set('provider', 'google');
      params.set('correo', googleUser.correo);
      params.set('nombre', googleUser.nombre || 'Google');
      params.set('apellido', googleUser.apellido || 'User');
      if (googleUser.googleId || googleUser.id) {
        params.set('googleId', googleUser.googleId || googleUser.id);
      }
      if (googleUser.picture) {
        params.set('picture', googleUser.picture);
      }

      return {
        requiresRegistration: true,
        provider: 'google',
        redirectTo: `${this.frontendBaseUrl.replace(/\/+$/, '')}/register?${params.toString()}`,
        profile: {
          correo: googleUser.correo,
          nombre: googleUser.nombre || 'Google',
          apellido: googleUser.apellido || 'User',
          googleId: googleUser.googleId || googleUser.id || null,
          picture: googleUser.picture || null,
        },
      };
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

    const accessToken = this.jwtService.sign(payload);

    return {
      requiresRegistration: false,
      redirectTo: `${this.frontendBaseUrl.replace(/\/+$/, '')}/home?token=${encodeURIComponent(
        accessToken,
      )}`,
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
      access_token: accessToken,
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
   * 📧 Generar token y enviar correo de recuperación
   */
  async requestPasswordReset(correo: string) {
    const user = await this.usersService.findByCorreo(correo);
    if (!user) {
      throw new NotFoundException('El correo no está registrado');
    }

    const expiresIn = this.configService.get<string>(
      'PASSWORD_RESET_TOKEN_EXPIRES_IN',
      '30m',
    );

    const token = this.jwtService.sign(
      {
        sub: user._id?.toString(),
        correo: user.correo,
        action: 'password-reset',
      },
      { expiresIn },
    );

    await this.mailService.sendPasswordResetEmail({
      to: user.correo,
      nombre: (user as any)?.nombre,
      token,
    });

    return {
      message: 'Email enviado con instrucciones para resetear la contraseña',
    };
  }

  /**
   * 🔐 Restablecer contraseña mediante token o correo
   */
  async resetPassword({
    token,
    correo,
    nuevaContrasena,
  }: PasswordResetPayload) {
    if (!nuevaContrasena || nuevaContrasena.trim().length < 6) {
      throw new BadRequestException(
        'Debes enviar una nueva contraseña de al menos 6 caracteres.',
      );
    }

    if (!token && !correo) {
      throw new BadRequestException(
        'Debes proporcionar el token recibido por correo o el correo registrado.',
      );
    }

    if (token) {
      let payload: { sub?: string; correo?: string; action?: string };
      try {
        payload = this.jwtService.verify(token);
      } catch (error) {
        throw new BadRequestException(
          'El token de recuperación es inválido o expiró.',
        );
      }

      if (payload?.action !== 'password-reset' || !payload?.sub) {
        throw new BadRequestException('El token de recuperación no es válido.');
      }

      const user =
        (await this.usersService.findByIdWithPassword(
          payload.sub.toString(),
        )) ||
        (payload.correo
          ? await this.usersService.findByCorreo(payload.correo)
          : null);

      if (!user) {
        throw new NotFoundException('Usuario no encontrado');
      }

      const hashed = await bcrypt.hash(nuevaContrasena, 10);
      user.contrasena = hashed;
      await user.save();

      return { message: 'Contraseña actualizada correctamente' };
    }

    return this.actualizarContrasena(correo as string, nuevaContrasena);
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
