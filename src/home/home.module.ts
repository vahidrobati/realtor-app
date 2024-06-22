import { ClassSerializerInterceptor, Module } from '@nestjs/common';
import { HomeService } from './home.service';
import { HomeController } from './home.controller';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { APP_INTERCEPTOR } from '@nestjs/core';

@Module({
  imports: [PrismaModule],
  providers: [HomeService, {
    provide: APP_INTERCEPTOR,
    useClass: ClassSerializerInterceptor
  }],
  controllers: [HomeController]
})
export class HomeModule {}
