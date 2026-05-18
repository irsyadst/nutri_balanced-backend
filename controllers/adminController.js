const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

const User = require("../models/userModel");
const FoodLog = require("../models/foodLogModel");
const Food = require("../models/foodModel");

exports.adminLogin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && user.role === "admin") {
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        const payload = { id: user._id, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "3h" });
        res.json({ message: "Admin login berhasil", token: token });
      } else {
        res.status(401).json({ message: "Email atau password salah." });
      }
    } else {
      res.status(401).json({ message: "Email atau password salah." });
    }
  } catch (error) {
    console.error("Admin Login Error:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({})
      .select("-password -googleId -profile")
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error("Admin Get Users Error:", error);
    res.status(500).json({ message: "Gagal mengambil data pengguna" });
  }
};

exports.createUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Nama, email, dan password wajib diisi",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email sudah terdaftar" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: "admin",
    });

    const savedUser = await user.save();
    const userResponse = savedUser.toObject();
    delete userResponse.password;

    res.status(201).json(userResponse);
  } catch (error) {
    console.error("Admin Create User Error:", error);
    res.status(500).json({ message: "Gagal membuat pengguna baru" });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email, password, role } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan" });
    }

    if (email !== user.email) {
      const existingUser = await User.findOne({ email, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(400).json({ message: "Email sudah digunakan" });
      }
    }

    user.name = name || user.name;
    user.email = email || user.email;
    user.role = "admin";

    if (password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
    }

    const updatedUser = await user.save();
    const userResponse = updatedUser.toObject();
    delete userResponse.password;

    res.json(userResponse);
  } catch (error) {
    console.error("Admin Update User Error:", error);
    res.status(500).json({ message: "Gagal memperbarui pengguna" });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;

    if (req.user.role === "admin" && req.user.id === userId) {
      const adminCount = await User.countDocuments({ role: "admin" });
      if (adminCount <= 1) {
        return res.status(400).json({
          message: "Tidak dapat menghapus admin terakhir",
        });
      }
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan" });
    }

    await user.deleteOne();
    res.json({ message: "Pengguna berhasil dihapus" });
  } catch (error) {
    console.error("Admin Delete User Error:", error);
    res.status(500).json({ message: "Gagal menghapus pengguna" });
  }
};

exports.getAllLogs = async (req, res) => {
  try {
    const logs = await FoodLog.find({})
      .sort({ createdAt: -1 })
      .limit(50)
      .populate("userId", "name email");
    res.json(logs);
  } catch (error) {
    console.error("Admin Get Logs Error:", error);
    res.status(500).json({ message: "Gagal mengambil data log" });
  }
};

const stringToArray = (str) => {
  if (!str || typeof str !== "string") return [];
  return str
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
};

exports.getAllFoods = async (req, res) => {
  try {
    const foods = await Food.find({}).sort({ name: 1 });
    res.json(foods);
  } catch (error) {
    console.error("Admin Get Foods Error:", error);
    res.status(500).json({ message: "Gagal mengambil data makanan" });
  }
};

exports.createFood = async (req, res) => {
  try {
    const {
      name,
      category,
      calories,
      proteins,
      carbs,
      fats,
      servingQuantity,
      servingUnit,
      dietaryTags,
      allergens,
    } = req.body;

    if (!name || !category || !calories || !servingQuantity || !servingUnit) {
      return res.status(400).json({
        message:
          "Field wajib (name, category, calories, servingQuantity, servingUnit) tidak boleh kosong.",
      });
    }

    const newFood = new Food({
      name,
      category,
      calories,
      proteins: proteins || 0,
      carbs: carbs || 0,
      fats: fats || 0,
      servingQuantity,
      servingUnit,
      dietaryTags: stringToArray(dietaryTags),
      allergens: stringToArray(allergens),
    });

    const createdFood = await newFood.save();
    res.status(201).json(createdFood);
  } catch (error) {
    console.error("Admin Create Food Error:", error);
    res.status(500).json({ message: "Gagal membuat data makanan" });
  }
};

exports.updateFood = async (req, res) => {
  try {
    const food = await Food.findById(req.params.id);

    if (food) {
      food.name = req.body.name || food.name;
      food.category = req.body.category || food.category;
      food.calories = req.body.calories || food.calories;
      food.proteins = req.body.proteins || food.proteins;
      food.carbs = req.body.carbs || food.carbs;
      food.fats = req.body.fats || food.fats;
      food.servingQuantity = req.body.servingQuantity || food.servingQuantity;
      food.servingUnit = req.body.servingUnit || food.servingUnit;

      food.dietaryTags = req.body.dietaryTags
        ? stringToArray(req.body.dietaryTags)
        : food.dietaryTags;
      food.allergens = req.body.allergens
        ? stringToArray(req.body.allergens)
        : food.allergens;

      const updatedFood = await food.save();
      res.json(updatedFood);
    } else {
      res.status(404).json({ message: "Data makanan tidak ditemukan" });
    }
  } catch (error) {
    console.error("Admin Update Food Error:", error);
    res.status(500).json({ message: "Gagal memperbarui data makanan" });
  }
};

exports.deleteFood = async (req, res) => {
  try {
    const food = await Food.findById(req.params.id);
    if (food) {
      await food.deleteOne(); 
      res.json({ message: "Data makanan berhasil dihapus" });
    } else {
      res.status(404).json({ message: "Data makanan tidak ditemukan" });
    }
  } catch (error) {
    console.error("Admin Delete Food Error:", error);
    res.status(500).json({ message: "Gagal menghapus data makanan" });
  }
};
