// ✅ src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from 'src/users/dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

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
    const user = await this.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    const payload = {
      email: user.email,
      sub: user._id?.toString(),
      roles: user.roles || ['usuario'],
      permisos: user.permisos || [],
    };

    return {
      user: {
        id: user._id?.toString(),
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        roles: user.roles || ['usuario'],
        permisos: user.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  /**
   * 🧾 Registro de usuario nuevo
   */
  async register(registerDto: RegisterDto) {
    const existing = await this.usersService.findByEmail(registerDto.email);
    if (existing) {
      throw new ConflictException('El correo ya está registrado');
    }

    const hashed = await bcrypt.hash(registerDto.password, 10);

    const createUserDto: CreateUserDto = {
      name: registerDto.name,
      lastName: registerDto.lastName,
      email: registerDto.email,
      password: hashed,
      roles: ['usuario'],
      permisos: [],
      isActive: true,
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;

    const payload = {
      email: user.email,
      sub: user._id?.toString(),
      roles: user.roles || ['usuario'],
      permisos: user.permisos || [],
    };

    return {
      user: {
        id: user._id?.toString(),
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        roles: user.roles || ['usuario'],
        permisos: user.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  /**
   * 👤 Obtener datos del usuario autenticado
   */
  async me(userId: string) {
    return this.usersService.findOne(userId);
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
      const createUserDto: CreateUserDto = {
        name: googleUser.firstName || 'Google',
        lastName: googleUser.lastName || 'User',
        email: googleUser.email,
        password: await bcrypt.hash('google-auth', 10),
        roles: ['usuario'],
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
      roles: plainUser.roles || ['usuario'],
      permisos: plainUser.permisos || [],
    };

    return {
      user: {
        id: userId,
        email: plainUser.email,
        name: plainUser.name,
        lastName: plainUser.lastName,
        roles: plainUser.roles || ['usuario'],
        permisos: plainUser.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
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
