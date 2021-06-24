import { getCustomRepository } from "typeorm"
import { compare } from "bcryptjs"
import { sign } from "jsonwebtoken"
import { UsersRepositories } from "../repositories/UsersRepositories"

interface IAuthenticateRequest {
  email: string;
  password: string;
}

class AuthenticateUserService {
  async execute({ email, password }: IAuthenticateRequest) {
    const usersRepositories = getCustomRepository(UsersRepositories);

    const user = await usersRepositories.findOne({
      email
    });

    if (!user) {
      throw new Error("Email/Password incorrect!");
    }

    const passwordMatch = await compare(password, user.password);

    if (!passwordMatch) {
      throw new Error("Email/Password incorrect!");
    }

    const token = sign({
      email: user.email
    }, "ecd1099d158993fc30bd243329f32be2", {
      subject: user.id,
      expiresIn: "1d"
    })

    return token;
  }
}

export { AuthenticateUserService }