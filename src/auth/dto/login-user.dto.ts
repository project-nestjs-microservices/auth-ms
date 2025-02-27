import {IsEmail, IsString, IsStrongPassword} from "class-validator";

export class LoginUserDto {


    @IsEmail()
    @IsEmail()
    email: string;

    @IsString()
    @IsStrongPassword()
    password: string;

}