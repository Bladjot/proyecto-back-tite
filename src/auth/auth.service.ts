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

  // 🔑 Validar credenciales para login normal
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...result } = user.toObject ? user.toObject() : user;
      return result;
    }
    return null;
  }

  // 🔑 Login normal con email y contraseña
  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    const userId = (user as any).id || user._id?.toString();

    const payload = {
      email: user.email,
      sub: userId,
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
    };

    return {
      user: {
        id: userId,
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  // 📝 Registro normal de usuario
  async register(registerDto: RegisterDto) {
    const existing = await this.usersService.findByEmail(registerDto.email);
    if (existing) {
      throw new ConflictException('El correo electrónico ya está registrado');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const createUserDto: CreateUserDto = {
      name: registerDto.name,
      lastName: registerDto.lastName,
      email: registerDto.email,
      password: hashedPassword,
      roles: ['cliente'],
      permisos: [],
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;

    const userId = (user as any).id || user._id?.toString();

    const payload = {
      email: user.email,
      sub: userId,
      roles: user.roles || ['cliente'],
      permisos: user.permisos || [],
    };

    return {
      user: {
        id: userId,
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        roles: user.roles || ['cliente'],
        permisos: user.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  // 👤 Perfil de usuario autenticado
  async me(userId: string) {
    return this.usersService.findOne(userId);
  }

  // 🌐 Login con Google
  async googleLogin(googleUser: any) {
    if (!googleUser) {
      throw new UnauthorizedException('Error en autenticación con Google');
    }

    let user = await this.usersService.findByEmail(googleUser.email);

    if (!user) {
      const createUserDto: CreateUserDto = {
        name: googleUser.firstName || 'Google',
        lastName: googleUser.lastName || 'User',
        email: googleUser.email,
        password: await bcrypt.hash('google-auth', 10), // 🔑 password dummy encriptado
        roles: ['user'],
        permisos: [],
        isActive: true,
      };

      user = await this.usersService.create(createUserDto);
    }

    const plainUser = user.toObject ? user.toObject() : user;
    const userId = (plainUser as any).id || plainUser._id?.toString();

    const payload = {
      email: plainUser.email,
      sub: userId,
      roles: plainUser.roles || ['user'],
      permisos: plainUser.permisos || [],
    };

    return {
      user: {
        id: userId,
        email: plainUser.email,
        name: plainUser.name,
        lastName: plainUser.lastName,
        roles: plainUser.roles || ['user'],
        permisos: plainUser.permisos || [],
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  // 🔍 Buscar usuario por email (para forgot/reset password)
  async findByEmail(email: string) {
    return this.usersService.findByEmail(email);
  }

  // 🔒 Actualizar contraseña
  async updatePassword(email: string, newPassword: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    return this.usersService.update(user._id, { password: hashedPassword });
  }
}
