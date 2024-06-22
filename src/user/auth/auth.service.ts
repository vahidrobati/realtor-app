import { Injectable, ConflictException, HttpException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from "bcryptjs";
import { UserType } from "@prisma/client";
import * as jwt from "jsonwebtoken";

interface SignupParams {
    email: string;
    password: string;
    name: string;
    phone: string;
}

interface SigninParams {
    email: string;
    password: string;    
}

@Injectable()
export class AuthService {
    constructor(private readonly prismaService:PrismaService){ }


    async signup({ email, password, name, phone }: SignupParams, userType: UserType){
        const userExist = await this.prismaService.user.findUnique({
            where: {
                email,
            },
        });
        if(userExist) 
        throw new ConflictException();
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = await this.prismaService.user.create(
            {
                data: {
                    email, 
                    phone,
                    name,
                    password: hashedPassword,
                    user_type: userType
                }
            }
        );

        return this.generateJWT(name, user.id);        
    }

    async signin({ email, password}: SigninParams){

        const user = await this.prismaService.user.findUnique({
            where:{
                email
            }
        });

        if(!user) 
            throw new HttpException("Invalid Token" , 400);

        const hashedPassword = user.password;

        const isValidPassword = await bcrypt.compare(password , hashedPassword);

        if(!isValidPassword) 
            throw new HttpException("Invalid Token" , 400);

        return await this.generateJWT(user.name, user.id);     

    }

    private async generateJWT(name: string, id: number){
        return jwt.sign({
            name,
            id
        }, process.env.JSON_TOKEN_KEY,
        {
            expiresIn: 360000
        });

    } 

    async generateProductKey(email: string, usertype: UserType){
        const seed = `${email} - ${usertype} - ${process.env.PRODUCT_KEY}`;

        return bcrypt.hash(seed, 10);

    } 
}
