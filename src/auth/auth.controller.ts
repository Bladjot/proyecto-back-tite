import {
  Controller,
  Post,
  Put,
  Patch,
  Body,
  Get,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Request,
  NotFoundException,
  BadRequestException,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Express } from 'express';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiBody, ApiConsumes } from '@nestjs/swagger';
import { UpdateProfileDetailsDto, UpdateProfileDetailsWithPhotoDto } from './dto/update-profile-details.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  getProfilePhotoPublicPath,
  profilePhotoFileFilter,
  profilePhotoStorage,
} from '../common/storage/profile-photo.storage';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 🔑 LOGIN
  @Post('login')
  @ApiOperation({ summary: 'Iniciar sesión con credenciales' })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  // 📝 REGISTER
  @Post('register')
  @ApiOperation({ summary: 'Registrar nuevo usuario' })
  @ApiBody({ type: RegisterDto })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  // 👤 GET PROFILE (requiere JWT)
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Obtener usuario autenticado (Equipo 6)',
    description:
      'Devuelve los datos básicos del usuario actual según su token JWT. Ideal para que el sistema u otros módulos conozcan quién está conectado.',
  })
  async getProfile(@Request() req) {
    // El guard JwtAuthGuard ya valida el token y carga req.user
    const userDocument = await this.authService.me(req.user.userId);
    const user =
      userDocument && userDocument.toObject
        ? userDocument.toObject()
        : userDocument;

    if (!user) throw new NotFoundException('Usuario no encontrado');

    // Evitamos exponer campos sensibles
    return {
      id: user.id || user._id?.toString(),
      name: user.name,
      lastName: user.lastName,
      email: user.email,
      rut: user.rut,
      roles: user.roles || [],
      permisos: user.permisos || [],
      foto: user.foto ?? null,
      telefono: user.telefono ?? null,
    };
  }

  // Perfil extendido: biografía y preferencias (requiere JWT)
  @UseGuards(JwtAuthGuard)
  @Get('profile-details')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Obtener biografía y preferencias del usuario autenticado',
  })
  async getProfileDetails(@Request() req) {
    const details = await this.authService.getProfileDetails(req.user.userId);
    return details;
  }

  // Variantes POST/PUT/PATCH para el front (mismo retorno)
  @UseGuards(JwtAuthGuard)
  @Post('profile-details')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Perfil (POST): biografía y preferencias' })
  async postProfileDetails(@Request() req) {
    return this.authService.getProfileDetails(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Put('profile-details')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Perfil (PUT): biografía y preferencias' })
  async putProfileDetails(@Request() req) {
    return this.authService.getProfileDetails(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile-details')
  @UseInterceptors(
    FileInterceptor('foto', {
      storage: profilePhotoStorage,
      fileFilter: profilePhotoFileFilter,
      limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
    }),
  )
  @ApiConsumes('multipart/form-data')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Actualizar nombre, apellido, biografía, foto y preferencias' })
  @ApiBody({ type: UpdateProfileDetailsWithPhotoDto })
  async patchProfileDetails(
    @Request() req,
    @Body() body: UpdateProfileDetailsDto,
    @UploadedFile() foto?: Express.Multer.File,
  ) {
    if (body.newPassword && !body.currentPassword) {
      throw new BadRequestException(
        'Debes enviar la contraseña actual para establecer una nueva.',
      );
    }

    const payload: {
      name?: string;
      lastName?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      email?: string;
      telefono?: string;
      currentPassword?: string;
      newPassword?: string;
    } = {
      name: body.name,
      lastName: body.lastName,
      biografia: body.biografia,
      email: body.email,
      telefono: body.telefono,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
    };

    if (typeof body.preferencias !== 'undefined') {
      if (body.preferencias === null || body.preferencias === '') {
        payload.preferencias = null;
      } else {
        try {
          payload.preferencias =
            typeof body.preferencias === 'string'
              ? JSON.parse(body.preferencias)
              : (body.preferencias as unknown as Record<string, any>);
        } catch (error) {
          throw new BadRequestException(
            'El campo preferencias debe ser un JSON válido.',
          );
        }
      }
    }

    if (foto) {
      payload.foto = getProfilePhotoPublicPath(foto.filename);
    }

    return this.authService.updateProfileDetails(req.user.userId, payload);
  }

  // ✅ CHECK PAGE PERMISSION
  @UseGuards(JwtAuthGuard)
  @Get('can-access')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verificar acceso a una página',
    description:
      'Comprueba si el usuario autenticado posee el permiso necesario para acceder a una página dada.',
  })
  async canAccessPage(@Request() req, @Query('page') page?: string) {
    if (!page) {
      throw new BadRequestException(
        'Debes especificar el identificador de la página en el query param "page".',
      );
    }

    const hasAccess = await this.authService.canAccessPage(
      req.user.userId,
      page,
    );

    return {
      page,
      hasAccess,
    };
  }

  // 🌐 LOGIN GOOGLE
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Iniciar sesión con Google OAuth2' })
  async googleAuth() {
    return { message: 'Redirigiendo a Google...' };
  }

  // 🌐 CALLBACK GOOGLE
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Callback de autenticación Google' })
  async googleAuthRedirect(@Request() req) {
    return this.authService.googleLogin(req.user);
  }

  // 📩 OLVIDÉ CONTRASEÑA
  @Post('forgot-password')
  @ApiOperation({ summary: 'Solicitar restablecimiento de contraseña' })
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
  @ApiOperation({ summary: 'Restablecer contraseña mediante token o email' })
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
