// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // ✅ Habilitar CORS para permitir conexiones desde el frontend
  app.enableCors({
    origin: true, // acepta cualquier origen
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  
  
  // ✅ Configuración global de validación de DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // elimina propiedades que no están en el DTO
      transform: true, // transforma automáticamente tipos (string → number, etc.)
    }),
  );
  
  // ✅ Prefijo global para todas las rutas de la API
  app.setGlobalPrefix('api');

  // ✅ Configuración de Swagger
  const config = new DocumentBuilder()
    .setTitle('API Auth & Profiles - GPI')
    .setDescription('Documentación de los endpoints de Autenticación y Perfiles')
    .setVersion('1.0')
    .addBearerAuth() // permite autenticación con JWT en Swagger
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  // 👉 Ruta extra para exportar el JSON de Swagger
  app.getHttpAdapter().get('/api-docs-json', (req, res) => {
    res.json(document);
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`✅ Aplicación ejecutándose en: http://localhost:${port}/api`);
  console.log(`📑 Swagger disponible en: http://localhost:${port}/api-docs`);
  console.log(`📂 Swagger JSON en: http://localhost:${port}/api-docs-json`);
}
bootstrap();
