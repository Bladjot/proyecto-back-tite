import { 
  CanActivate, 
  ExecutionContext, 
  Injectable, 
  ForbiddenException 
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from 'src/common/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) return true;

    const request = context.switchToHttp().getRequest();
    const { user } = request;

    if (!user || !user.roles) {
      throw new ForbiddenException('Usuario sin rol asignado');
    }

    // 🧠 Validar que el usuario tenga al menos uno de los roles requeridos
    const hasRole = user.roles.some((role: string) =>
      requiredRoles.includes(role)
    );

    if (!hasRole) {
      throw new ForbiddenException('Acceso denegado: rol insuficiente');
    }

    return true;
  }
}
