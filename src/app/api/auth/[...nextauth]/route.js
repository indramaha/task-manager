require("dotenv").config();
import NextAuth from "next-auth/next";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { compare } from "bcrypt";
import { db } from "@/lib/db";

export const authOptions = {
  adapter: PrismaAdapter(db),
  session: {
    strategy: "jwt",
    maxAge: 24 * 60 * 60,
  },
  debug: process.env.NODE_ENV,
  secret: process.env.NEXTAUTH_SECRET,
  //page
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
          return null;
        }

        const existsUser = await db.user.findUnique({
          where: {
            email: credentials.email,
          },
          include: {
            accounts: true,
          },
        });

        if (!existsUser) {
          return null;
        }

        if (
          existsUser.accounts &&
          existsUser.accounts.length > 0 &&
          existsUser.accounts[0].provider === "google"
        ) {
          return null;
        }
        if (existsUser.password) {
          const passwordMatch = await compare(
            credentials.password,
            existsUser.password
          );
          if (!passwordMatch) {
            return null;
          }
        }
        return {
          id: existsUser.id,
          email: existsUser.email,
          name: existsUser.name,
        };
      },
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_ID,
      clientSecret: process.env.GOOGLE_SECRET,
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
        session.user.email = token.email;
        session.user.name = token.name;
        session.user.expires = new Date(session.expires).toLocaleString();
      }
      return session;
    },
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
