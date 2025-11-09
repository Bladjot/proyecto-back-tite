import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { VendorAccreditationsService } from './vendor-accreditations.service';
import { VendorAccreditationsController } from './vendor-accreditations.controller';
import {
  VendorAccreditation,
  VendorAccreditationSchema,
} from './schemas/vendor-accreditation.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: VendorAccreditation.name, schema: VendorAccreditationSchema },
    ]),
  ],
  controllers: [VendorAccreditationsController],
  providers: [VendorAccreditationsService],
})
export class VendorAccreditationsModule {}
