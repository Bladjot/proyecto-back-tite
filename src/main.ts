import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Habilitar CORS para permitir conexiones desde el frontend
  app.enableCors({
    origin: 'http://localhost:5173', // URL del frontend (Vite usa 5173 por defecto)
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });
  
  // Configuración global de validación de DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Elimina propiedades que no están en el DTO
      transform: true,  // Transforma los datos recibidos al tipo del DTO
    }),
  );
  
  // Prefijo global para todas las rutas de la API
  app.setGlobalPrefix('api');

  // ⚡ Configuración Swagger
  const config = new DocumentBuilder()
    .setTitle('API Auth & Profiles - GPI')
    .setDescription('Documentación de los endpoints de Autenticación y Perfiles')
    .setVersion('1.0')
    .addBearerAuth() // Para que Swagger pueda enviar JWT en headers
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`✅ Aplicación ejecutándose en: http://localhost:${port}/api`);
  console.log(`📑 Swagger disponible en: http://localhost:${port}/api-docs`);
}
bootstrap();
