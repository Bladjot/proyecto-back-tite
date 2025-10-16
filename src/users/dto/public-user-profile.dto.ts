export class PublicUserProfileDto {
  id: string;
  name: string;
  lastName: string;
  email: string;
  isActive: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
