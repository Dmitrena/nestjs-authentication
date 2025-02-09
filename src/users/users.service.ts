import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { CreateUserDto } from './dto/create-user-dto';
import { hash } from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async create(createUserDto: CreateUserDto) {
    await new this.userModel({
      ...createUserDto,
      password: await hash(createUserDto.password, 10),
    }).save();
  }

  async getUser(query: FilterQuery<User>) {
    const user = (await this.userModel.findOne(query))?.toObject();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async getUsers() {
    return this.userModel.find({});
  }

  async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
    return this.userModel.findOneAndUpdate(query, data);
  }

  async getOrCreateUser(data: CreateUserDto) {
    const user = await this.userModel.findOne({ email: data.email });
    if (user) {
      return user;
    }
    return this.create(data);
  }
}
