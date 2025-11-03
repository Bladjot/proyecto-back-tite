import { CanActivate, ExecutionContext, Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as https from 'https';
import { URLSearchParams } from 'url';

@Injectable()
export class RecaptchaGuard implements CanActivate {
  private async validateToken(token: string, remoteip?: string): Promise<boolean> {
    if (!token) return false;

    const secret = process.env.RECAPTCHA_SECRET_KEY;
    if (!secret) return false;

    const params = new URLSearchParams({ secret, response: token });
    if (remoteip) params.set('remoteip', remoteip);

    const options = {
      hostname: 'www.google.com',
      path: '/recaptcha/api/siteverify?' + params.toString(),
      method: 'POST',
    } as const;

    return new Promise<boolean>((resolve) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed && parsed.success === true);
          } catch (e) {
            resolve(false);
          }
        });
      });

      req.on('error', () => resolve(false));
      req.end();
    });
  }

  async canActivate(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    const token = req.body?.recaptchaToken || req.headers['x-recaptcha-token'];

    if (!token) throw new BadRequestException('reCAPTCHA token missing');

    const valid = await this.validateToken(token, req.ip);
    if (!valid) throw new UnauthorizedException('reCAPTCHA validation failed');

    return true;
  }
}
