import {
  Controller,
  Post,
  Body,
  Get,
  UseGuards,
  Request,
  NotFoundException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 🔑 LOGIN
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  // 📝 REGISTER
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  // 👤 GET PROFILE (requiere JWT)
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req) {
    return this.authService.me(req.user.userId);
  }

  // 🌐 LOGIN GOOGLE
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    return { message: 'Redirigiendo a Google...' };
  }

  // 🌐 CALLBACK GOOGLE
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Request() req) {
    return this.authService.googleLogin(req.user);
  }

  // 📩 OLVIDÉ CONTRASEÑA
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    const user = await this.authService.findByEmail(email);

    if (!user) {
      throw new NotFoundException('El correo no está registrado');
    }

    // Aquí normalmente generas token y envías email
    return {
      message: 'Email enviado con instrucciones para resetear la contraseña',
    };
  }

  // 🔒 RESETEAR CONTRASEÑA
  @Post('reset-password')
  async resetPassword(
    @Body('email') email: string,
    @Body('newPassword') newPassword: string,
  ) {
    const user = await this.authService.findByEmail(email);

    if (!user) {
      throw new NotFoundException('El correo no está registrado');
    }

    await this.authService.updatePassword(email, newPassword);

    return { message: 'Contraseña actualizada correctamente' };
  }
}
