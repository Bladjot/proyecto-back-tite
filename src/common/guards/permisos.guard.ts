import { CanActivate, ExecutionContext, Injectable, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISOS_KEY } from 'src/common/decorators/permisos.decorator';

@Injectable()
export class PermisosGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermisos = this.reflector.getAllAndOverride<string[]>(PERMISOS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredPermisos) return true;

    const { user } = context.switchToHttp().getRequest();
    if (!user || !user.permisos) {
      throw new ForbiddenException('Usuario sin permisos asignados');
    }

    const tienePermiso = requiredPermisos.every((permiso) =>
      user.permisos.includes(permiso),
    );

    if (!tienePermiso) {
      throw new ForbiddenException('Acceso denegado: permisos insuficientes');
    }

    return true;
  }
}
