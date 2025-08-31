import { 
  IsEmail, 
  IsNotEmpty, 
  IsString, 
  MinLength, 
  IsArray, 
  IsOptional, 
  IsBoolean 
} from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  lastName: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  // 👇 ahora arrays de roles y permisos
  @IsOptional()
  @IsArray()
  roles?: string[];

  @IsOptional()
  @IsArray()
  permisos?: string[];

  // 👇 añadido para Google login y control de estado
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

