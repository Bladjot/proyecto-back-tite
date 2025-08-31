import { Injectable, UnauthorizedException } from '@nestjs/common';
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

    // 👇 arreglado con cast a any
    const userId = (user as any).id || user._id?.toString();

    const payload = { 
      email: user.email, 
      sub: userId, 
      roles: user.roles || ['cliente'], 
      permisos: user.permisos || [] 
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

  // 🔑 Registro normal de usuario
  async register(registerDto: RegisterDto) {
    const createUserDto: CreateUserDto = {
      name: registerDto.name,
      lastName: registerDto.lastName,
      email: registerDto.email,
      password: registerDto.password,
      roles: ['cliente'],   // 👈 rol por defecto
      permisos: [],         // 👈 sin permisos iniciales
    };

    const newUser = await this.usersService.create(createUserDto);
    const user = newUser.toObject ? newUser.toObject() : newUser;

    // 👇 arreglado con cast a any
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

  // 🔑 Perfil de usuario autenticado
  async me(userId: string) {
    return this.usersService.findOne(userId);
  }

  // 🔑 Login con Google
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
        password: 'google-auth', // 👈 password dummy
        roles: ['user'],         // 👈 rol por defecto
        permisos: [],
        isActive: true,
      };

      user = await this.usersService.create(createUserDto);
    }

    // 3. Convertir a objeto plano si es un Document de Mongoose
    const plainUser = user.toObject ? user.toObject() : user;

    // 👇 arreglado con cast a any
    const userId = (plainUser as any).id || plainUser._id?.toString();

    // 4. Generar JWT con roles y permisos
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
}
