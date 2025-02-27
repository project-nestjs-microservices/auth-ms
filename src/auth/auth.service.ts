import {Injectable, Logger, OnModuleInit} from '@nestjs/common';
import {PrismaClient} from "@prisma/client";
import {RpcException} from "@nestjs/microservices";
import {LoginUserDto, RegisterUserDto} from "./dto";
import * as bcrypt from 'bcrypt'
import {JwtService} from "@nestjs/jwt";
import {JWTPayload} from "./interfaces/jwt-payload.interface";
import {envs} from "../config";

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger("AuthService");

    constructor(
        private readonly jwtService: JwtService,
    ) {
        super();
    }

    onModuleInit() {
        this.$connect()
        this.logger.log("MongoDB connection started");
    }

    async signJwt( payload: JWTPayload ){
        return this.jwtService.sign(payload)
    }

    async registerUser(registerUserDto: RegisterUserDto){
        const { email, name, password } = registerUserDto

        try {

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            })

            if( user ){
                throw new RpcException({
                    status: 400,
                    message: "User already exists"
                })
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    name,
                    password: bcrypt.hashSync(password, 10)
                }
            })

            const { password: __, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJwt(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            })
        }

    }

    async loginUser(loginUserDto: LoginUserDto){

        const { email, password } = loginUserDto

        try {

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            })

            if( !user ){
                throw new RpcException({
                    status: 400,
                    message: "User/Password not valid"
                })
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password)

            if(!isPasswordValid){
                throw new RpcException({
                    status: 400,
                    message: "User/Password incorrect"
                })
            }



            const { password: __, ...rest } = user;

            return {
                user: rest,
                token: await this.signJwt(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            })
        }

    }

    async verifyToken(token: string){

        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            })

            return {
                user,
                token: await this.signJwt(user)
            }

        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            })
        }

    }

}
