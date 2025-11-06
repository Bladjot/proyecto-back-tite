export class PublicUserProfileDto {
  id: string;
  name: string;
  lastName: string;
  email: string;
  rut: string;
  isActive: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
