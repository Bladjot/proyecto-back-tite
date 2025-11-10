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
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Express, Response } from 'express';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiBody, ApiConsumes } from '@nestjs/swagger';
import { UpdateProfileDetailsDto, UpdateProfileDetailsWithPhotoDto } from './dto/update-profile-details.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { ConfigService } from '@nestjs/config';
import {
  getProfilePhotoPublicPath,
  profilePhotoFileFilter,
  profilePhotoStorage,
} from '../common/storage/profile-photo.storage';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  // ðŸ”‘ LOGIN
  @Post('login')
  @ApiOperation({ summary: 'Iniciar sesiÃ³n con credenciales' })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  // ðŸ“ REGISTER
  @Post('register')
  @ApiOperation({ summary: 'Registrar nuevo usuario' })
  @ApiBody({ type: RegisterDto })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  // ðŸ‘¤ GET PROFILE (requiere JWT)
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Obtener usuario autenticado (Equipo 6)',
    description:
      'Devuelve los datos bÃ¡sicos del usuario actual segÃºn su token JWT. Ideal para que el sistema u otros mÃ³dulos conozcan quiÃ©n estÃ¡ conectado.',
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

  // Perfil extendido: biografÃ­a y preferencias (requiere JWT)
  @UseGuards(JwtAuthGuard)
  @Get('profile-details')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Obtener biografÃ­a y preferencias del usuario autenticado',
  })
  async getProfileDetails(@Request() req) {
    const details = await this.authService.getProfileDetails(req.user.userId);
    return details;
  }

  // Variantes POST/PUT/PATCH para el front (mismo retorno)
  @UseGuards(JwtAuthGuard)
  @Post('profile-details')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Perfil (POST): biografÃ­a y preferencias' })
  async postProfileDetails(@Request() req) {
    return this.authService.getProfileDetails(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Put('profile-details')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Perfil (PUT): biografÃ­a y preferencias' })
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
  @ApiOperation({ summary: 'Actualizar nombre, apellido, biografÃ­a, foto y preferencias' })
  @ApiBody({ type: UpdateProfileDetailsWithPhotoDto })
  async patchProfileDetails(
    @Request() req,
    @Body() body: UpdateProfileDetailsDto,
    @UploadedFile() foto?: Express.Multer.File,
  ) {
    if (body.newPassword && !body.currentPassword) {
      throw new BadRequestException(
        'Debes enviar la contraseÃ±a actual para establecer una nueva.',
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
            'El campo preferencias debe ser un JSON vÃ¡lido.',
          );
        }
      }
    }

    if (foto) {
      payload.foto = getProfilePhotoPublicPath(foto.filename);
    }

    return this.authService.updateProfileDetails(req.user.userId, payload);
  }

  // âœ… CHECK PAGE PERMISSION
  @UseGuards(JwtAuthGuard)
  @Get('can-access')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verificar acceso a una pÃ¡gina',
    description:
      'Comprueba si el usuario autenticado posee el permiso necesario para acceder a una pÃ¡gina dada.',
  })
  async canAccessPage(@Request() req, @Query('page') page?: string) {
    if (!page) {
      throw new BadRequestException(
        'Debes especificar el identificador de la pÃ¡gina en el query param "page".',
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

  // ðŸŒ LOGIN GOOGLE
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Iniciar sesiÃ³n con Google OAuth2' })
  async googleAuth() {
    return { message: 'Redirigiendo a Google...' };
  }

  // ðŸŒ CALLBACK GOOGLE
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Callback de autenticación Google' })
  async googleAuthRedirect(@Request() req, @Res() res: Response) {
    const authResult = await this.authService.googleLogin(req.user);
    const redirectUrl = this.buildGoogleRedirectUrl(
      authResult.redirectTo,
      authResult.access_token,
    );

    return res.redirect(redirectUrl);
  }

  private buildGoogleRedirectUrl(
    redirectPath: string | undefined,
    accessToken: string,
  ): string {
    const frontendBaseUrl =
      this.configService.get<string>('FRONTEND_BASE_URL') ??
      'http://localhost:5173';
    const fallbackHomePath = this.configService.get<string>(
      'FRONTEND_HOME_PATH',
      '/home',
    );
    const targetPath =
      redirectPath && redirectPath.trim().length > 0
        ? redirectPath
        : fallbackHomePath || '/home';
    const normalizedPath = targetPath.startsWith('/')
      ? targetPath
      : `/${targetPath}`;

    let targetUrl: URL;
    try {
      targetUrl = new URL(frontendBaseUrl);
    } catch {
      targetUrl = new URL('http://localhost:5173');
    }

    targetUrl.pathname = normalizedPath;
    if (accessToken) {
      targetUrl.searchParams.set('access_token', accessToken);
    }

    return targetUrl.toString();
  }
  // ðŸ“© OLVIDÃ‰ CONTRASEÃ‘A
  @Post('forgot-password')
  @ApiOperation({ summary: 'Solicitar restablecimiento de contraseÃ±a' })
  async forgotPassword(@Body('email') email: string) {
    const user = await this.authService.findByEmail(email);

    if (!user) {
      throw new NotFoundException('El correo no estÃ¡ registrado');
    }

    // AquÃ­ normalmente generas token y envÃ­as email
    return {
      message: 'Email enviado con instrucciones para resetear la contraseÃ±a',
    };
  }

  // ðŸ”’ RESETEAR CONTRASEÃ‘A
  @Post('reset-password')
  @ApiOperation({ summary: 'Restablecer contraseÃ±a mediante token o email' })
  async resetPassword(
    @Body('email') email: string,
    @Body('newPassword') newPassword: string,
  ) {
    const user = await this.authService.findByEmail(email);

    if (!user) {
      throw new NotFoundException('El correo no estÃ¡ registrado');
    }

    await this.authService.updatePassword(email, newPassword);

    return { message: 'ContraseÃ±a actualizada correctamente' };
  }
}


