import db from "../../../lib/db";
import { NextResponse } from "next/server";
import { hash } from "bcrypt";
import validator from "validator";

export async function POST(req) {
  try {
    const body = await req.json();
    const { name, email, password } = body;

    //cek if email is valid
    if (!validator.isEmail(email)) {
      return NextResponse.json(
        { message: "Invalid email" },
        { status: 400 }
      );
    }

    //cek if name less than 5 characters
    if (name.length < 5) {
      return NextResponse.json(
        { message: "Username must be at least 5 characters" },
        { status: 400 }
      );
    }

    //cek if email already exist
    const user = await db.user.findUnique({
      where: {
        email: email,
      },
    });
    if (user) {
      return NextResponse.json(
        { message: "Email already exist" },
        { status: 400 }
      );
    }

    //if password is less than 6 characters
    if (password.length < 6) {
      return NextResponse.json(
        { message: "Password must be at least 6 characters" },
        { status: 400 }
      );
    }

    //hash password
    const hashedPassword = await hash(password, 10);

    //create user
    const newUser = await db.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    //return user
    const { password: _, ...rest } = newUser;

    return NextResponse.json(
      {
        user: rest,
        message: "User created successfully",
      },
      { status: 201 }
    );
  } catch (error) {
    return NextResponse.json(
      { message: "Something went wrong" },
      { status: 500 }
    );
  }
}
