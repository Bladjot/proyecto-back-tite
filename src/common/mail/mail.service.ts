import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

type PasswordResetPayload = {
  to: string;
  nombre?: string | null;
  token: string;
};

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: nodemailer.Transporter | null;
  private readonly fromAddress: string;
  private readonly frontendBaseUrl: string;

  constructor(private readonly configService: ConfigService) {
    const host = configService.get<string>('SMTP_HOST');
    const port = Number(configService.get<string>('SMTP_PORT') ?? 587);
    const secure =
      String(configService.get<string>('SMTP_SECURE') ?? 'false').toLowerCase() === 'true';
    const user = configService.get<string>('SMTP_USER');
    const pass = configService.get<string>('SMTP_PASSWORD');

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: {
          user,
          pass,
        },
      });
    } else {
      this.logger.warn(
        'Configuración SMTP incompleta. El envío de correos está deshabilitado hasta que se definan las variables SMTP_HOST, SMTP_USER y SMTP_PASSWORD.',
      );
      this.transporter = null;
    }

    const from = configService.get<string>('EMAIL_FROM') || user;
    this.fromAddress = from || 'PulgaShop <no-reply@pulga-shop.local>';

    this.frontendBaseUrl =
      configService.get<string>('FRONTEND_BASE_URL') ||
      configService.get<string>('FRONTEND_URL') ||
      'http://localhost:5173';
  }

  private getTransporter(): nodemailer.Transporter {
    if (!this.transporter) {
      throw new InternalServerErrorException(
        'El servicio de correo no está configurado. Contacta a un administrador.',
      );
    }
    return this.transporter;
  }

  private buildResetPasswordUrl(token: string): string {
    const path =
      this.configService.get<string>('FRONTEND_PASSWORD_RESET_PATH') ||
      '/auth/reset-password';
    const base = this.frontendBaseUrl.replace(/\/+$/, '');
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${base}${normalizedPath}?token=${encodeURIComponent(token)}`;
  }

  async sendPasswordResetEmail(payload: PasswordResetPayload): Promise<void> {
    const transporter = this.getTransporter();
    const resetUrl = this.buildResetPasswordUrl(payload.token);
    const greetingName = payload.nombre?.trim() || 'usuario';

    const subject = 'Recupera tu contraseña';
    const textContent = [
      `Hola ${greetingName},`,
      '',
      'Recibimos una solicitud para restablecer tu contraseña en PulgaShop.',
      `Puedes crear una nueva contraseña usando el siguiente enlace: ${resetUrl}`,
      '',
      'Si tú no solicitaste este cambio, simplemente ignora este mensaje.',
    ].join('\n');

    const htmlContent = `
      <p>Hola <strong>${greetingName}</strong>,</p>
      <p>Recibimos una solicitud para restablecer tu contraseña en PulgaShop.</p>
      <p>
        Haz clic en el siguiente botón o copia y pega el enlace en tu navegador:
      </p>
      <p>
        <a href="${resetUrl}" style="background:#2bbf5c;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;display:inline-block">
          Restablecer contraseña
        </a>
      </p>
      <p style="word-break:break-all;">Enlace alternativo: <a href="${resetUrl}">${resetUrl}</a></p>
      <p>Si tú no solicitaste este cambio puedes ignorar este mensaje.</p>
      <p>— Equipo PulgaShop</p>
    `;

    try {
      await transporter.sendMail({
        from: this.fromAddress,
        to: payload.to,
        subject,
        text: textContent,
        html: htmlContent,
      });
    } catch (error) {
      this.logger.error('Error enviando correo de recuperación', error.stack || error.message);
      throw new InternalServerErrorException(
        'No se pudo enviar el correo de recuperación. Inténtalo más tarde.',
      );
    }
  }
}
