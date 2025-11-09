import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
  Request,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { VendorAccreditationsService } from './vendor-accreditations.service';
import { CreateVendorAccreditationDto } from './dto/create-vendor-accreditation.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';

@ApiTags('Vendor Accreditations')
@Controller('vendor-accreditations')
export class VendorAccreditationsController {
  constructor(
    private readonly vendorAccreditationsService: VendorAccreditationsService,
  ) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Crear solicitud de acreditación de vendedor',
  })
  create(
    @Body() dto: CreateVendorAccreditationDto,
    @Request() req,
  ) {
    return this.vendorAccreditationsService.create(dto, req.user?.userId);
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Listar todas las solicitudes (solo admin)',
  })
  findAll() {
    return this.vendorAccreditationsService.findAll();
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Eliminar una solicitud de acreditación (solo admin)',
  })
  remove(@Param('id') id: string) {
    return this.vendorAccreditationsService.remove(id);
  }
}
