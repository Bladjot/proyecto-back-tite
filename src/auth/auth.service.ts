import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from 'src/users/schemas/dto/create-user.dto';

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
      const { password, ...result } = user.toObject();
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

    const payload = { email: user.email, sub: user.id, role: user.role };

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        role: user.role,
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  // 🔑 Registro normal de usuario
  async register(registerDto: RegisterDto) {
    const createUserDto: CreateUserDto = {
      name: registerDto.name,
      lastName: registerDto.lastName,
      email: registerDto.email,
      password: registerDto.password,
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;
    const userId = user.id || user._id?.toString();

    const payload = {
      email: user.email,
      sub: userId,
      role: user.role,
    };

    return {
      user: {
        id: userId,
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        role: user.role,
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  // 🔑 Perfil de usuario autenticado
  async me(userId: string) {
    return this.usersService.findOne(userId);
  }

  // 🔑 Login con Google (nuevo)
  async googleLogin(googleUser: any) {
    if (!googleUser) {
      throw new UnauthorizedException('Error en autenticación con Google');
    }

    // 1. Buscar usuario en la base de datos
    let user = await this.usersService.findByEmail(googleUser.email);

    // 2. Si no existe, crearlo
    if (!user) {
      const createUserDto: CreateUserDto = {
        name: googleUser.firstName || 'Google',
        lastName: googleUser.lastName || 'User',
        email: googleUser.email,
        password: 'google-auth', // password dummy
        role: 'user',
        isActive: true,
      };

      user = await this.usersService.create(createUserDto);
    }

    // 3. Convertir a objeto plano si es un Document de Mongoose
    const plainUser = user.toObject ? user.toObject() : user;
    const userId = plainUser.id || plainUser._id?.toString();

    // 4. Generar JWT propio
    const payload = {
      email: plainUser.email,
      sub: userId,
      role: plainUser.role,
    };

    return {
      user: {
        id: userId,
        email: plainUser.email,
        name: plainUser.name,
        lastName: plainUser.lastName,
        role: plainUser.role,
      },
      access_token: this.jwtService.sign(payload),
    };
  }
}
