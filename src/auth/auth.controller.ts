import {
  Controller,
  Post,
  Body,
  Get,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req) {
    return this.authService.me(req.user.userId);
  }

  // 🚀 Redirige a Google para login
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    return { message: 'Redirigiendo a Google...' };
  }

  // 🚀 Callback después del login de Google
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Request() req) {
    // Aquí delegamos a AuthService para crear usuario si no existe
    return this.authService.googleLogin(req.user);
  }
}
