import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { db } from "./db";
import { compare } from "bcrypt";

export const authOptions = {
  adapter: PrismaAdapter(db),
  session: {
    strategy: "jwt",
    maxAge: "1d",
  },
  //untuk login gunakan endpoint /login
  // pages: {
  //   signIn: "/login",
  // },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {
          label: "Email",
          type: "email",
          placeholder: "example@email.com",
        },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
            return null
        }

        const existsUser = await db.user.findUnique({
            where: {
                email: credentials.email
            }
        })

        if (!existsUser) {
            return null
        }

        const passwordMatch = await compare(credentials.password, existsUser.password)

        if (!passwordMatch) {
            return null
        }

        return {
            id: existsUser.id,
            email: existsUser.email,
            username: existsUser.username
        }
      },
    }),
  ],
};
