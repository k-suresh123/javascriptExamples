Below is complete, clean and production-ready code showing:

✅ How NestJS generates access + refresh tokens
✅ How backend sets refresh token inside HTTP-only cookie
✅ How backend reads that cookie on /auth/refresh
✅ How backend issues new tokens
✅ How to clear the cookie on logout

✔ Refresh token is stored in HTTP-only cookie
✔ Frontend CANNOT read it
✔ Browser sends it automatically to /auth/refresh

// auth.service.ts
import { Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthService {
  constructor(private jwt: JwtService) {}

  // Generate Access Token
  generateAccessToken(userId: string) {
    return this.jwt.sign(
      { sub: userId },
      {
        expiresIn: "2m",       // 2 minutes
        secret: process.env.JWT_ACCESS_SECRET,
      },
    );
  }

  // Generate Refresh Token
  generateRefreshToken(userId: string) {
    return this.jwt.sign(
      { sub: userId },
      {
        expiresIn: "7d",       // 7 days
        secret: process.env.JWT_REFRESH_SECRET,
      },
    );
  }
}

LOGIN  - SET REFRESH TOKEN COOKIE

// auth.controller.ts
import {
  Controller,
  Post,
  Body,
  Res,
} from "@nestjs/common";
import { Response } from "express";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post("login")
  async login(@Body() body: any, @Res() res: Response) {
    const { email, password } = body;

    // Fake auth for example
    const userId = "123"; // after validating credentials

    const accessToken = this.authService.generateAccessToken(userId);
    const refreshToken = this.authService.generateRefreshToken(userId);

    // IMPORTANT → Backend sets the cookie
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/auth/refresh",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.send({
      success: true,
      accessToken,
    });
  }
}

✅ 3. Refresh Token – Read Cookie & Issue New Token
// auth.controller.ts (continued)

import { Req } from "@nestjs/common";
import { Request } from "express";
import * as jwt from "jsonwebtoken";

@Post("refresh")
async refresh(@Req() req: Request, @Res() res: Response) {
  const refreshToken = req.cookies["refresh_token"]; // <-- READ COOKIE HERE

  if (!refreshToken) {
    return res.status(401).send({ message: "No refresh token cookie" });
  }

  // Validate refresh token
  try {
    const payload = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    ) as any;

    // Issue new tokens
    const accessToken = this.authService.generateAccessToken(payload.sub);
    const newRefreshToken = this.authService.generateRefreshToken(payload.sub);

    // Update cookie with new refresh token (rotation)
    res.cookie("refresh_token", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/auth/refresh",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.send({
      success: true,
      accessToken,
    });

  } catch (err) {
    return res.status(401).send({ message: "Invalid refresh token" });
  }
}


✔ Cookie is automatically read
✔ Backend validates refresh token
✔ Generates new tokens
✔ Sends refreshed accessToken to frontend
✔ Sets new cookie with new refresh token

✅ 4. Logout – Clear Cookie
@Post("logout")
logout(@Res() res: Response) {
  res.clearCookie("refresh_token", {
    path: "/auth/refresh",
  });

  return res.send({ success: true });
}

🔥 5. How Angular Sends Cookie in Request (VERY IMPORTANT)

You MUST enable credentials:

Add this in Angular HTTP call:
this.http.post('/auth/refresh', {}, { withCredentials: true });

Global config (Interceptor optional)
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler) {

    const authReq = req.clone({
      withCredentials: true // <-- ensures cookies are sent
    });

    return next.handle(authReq);
  }
}


✔ Browser automatically attaches refresh_token cookie
✔ Frontend does not need to read or write it
