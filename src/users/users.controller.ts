import { CurrentUser } from './../auth/current-user.decorator';
import { JwtAuthGuard } from './../auth/guards/jwt-auth.guard';
import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user-dto';
import { UsersService } from './users.service';
import { User } from './schema/user.schema';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async createUser(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(@CurrentUser() user: User) {
    console.log(user);
    return this.usersService.getUsers();
  }
}
