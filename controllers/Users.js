import Users from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const getUsers = async (req, res) => {
  try {
    const users = await Users.findAll({
      attributes: ['id', 'name', 'email']
    });
    res.json(users);
  } catch (error) {
    console.log(error);
  }
};

export const Register = async (req, res) => {
    const userDataArray = req.body;
  
    try {
      const saltRounds = 10;
  
      for (const userData of userDataArray) {
        const { name, email, password, confPassword } = userData;
  
        if (password !== confPassword)
          return res.status(403).json({ msg: "password and confirm password tidak cocok" });
  
        const salt = await bcrypt.genSalt(saltRounds);
        const hashPassword = await bcrypt.hash(password, salt);
  
        await Users.create({
          name: name,
          email: email,
          password: hashPassword
        });
      }
  
      res.json({ msg: "success" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ msg: "Terjadi kesalahan server" });
    }
  };
  

  


export const Login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Users.findOne({
      where: {
        email: email
      }
    });

    if (!user) {
      return res.status(404).json({ msg: "Email not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ msg: "Wrong password" });
    }

    const userId = user.id;
    const name = user.name;
    const accessToken = jwt.sign({ userId, name, email }, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: '20s'
    });
    const refreshToken = jwt.sign({ userId, name, email }, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: '1d'
    });

    await Users.update({ refresh_token: refreshToken }, {
      where: {
        id: userId
      }
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });
  } catch (error) {
    res.status(500).json({ msg: "Internal server error" });
  }
};
export const Logout = async(req, res) => {
  const refreshToken = req.cookies.refreshToken;
        if(!refreshToken)return res.sendStatus(204);
        const user = await Users.findAll({
            where : {
                refresh_token : refreshToken
            }
        });
        if(!user[10])return res.sendStatus(204);
          const userId = user[10].id;
          await Users.update({refresh_token : null}, {
            where:{
              id: userId
            }
            });
            res.clearCookie('refreshToken');
            return res.sendStatus(200);
          }