import express from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';
import serviceAccountKey from './react-js-blog-website-yt-6e394-firebase-adminsdk-602yf-a9c4626d6a.json' assert { type: 'json' };
import { getAuth } from 'firebase-admin/auth';
import User from './Schema/User.js';
import aws from 'aws-sdk';
import Blog from './Schema/Blog.js';
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey),
});

const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

const server = express();
const port = process.env.PORT || 3000; // Use Vercel's port

// Middleware
server.use(express.json());
server.use(cors({ origin: 'https://blog-it-out.netlify.app' }));

// Connect to MongoDB
mongoose.connect(process.env.DB_LOCATION, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("Connected to MongoDB");
}).catch(err => {
    console.error("MongoDB connection error:", err);
});

// Set up AWS S3
const s3 = new aws.S3({
    region: 'ap-south-1',
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// Generate upload URL for images
const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;
    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'blogging-website-yt-tutorial1',
        Key: imageName,
        Expires: 1000,
        ContentType: 'image/jpeg',
    });
};

// JWT verification middleware
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No access token found" });

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Access token is invalid" });
        req.user = user.id;
        next();
    });
};

// Format user data for response
const formatDataToSend = (user) => {
    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY);
    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
    };
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
};

// Routes
server.get('/get-upload-url', async (req, res) => {
    try {
        const url = await generateUploadURL();
        res.status(200).json({ uploadURL: url });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const generateUsername = async (email) => {
    let username = email.split('@')[0];

    let isUsernameExists = await User.exists({ "personal_info.username": username });

    if (isUsernameExists) {
        username += nanoid().substring(0, 5);
    }

    return username;
};

server.post("/signup", async (req, res) => {
    const { fullname, email, password } = req.body;

    if (!fullname || fullname.length < 3) {
        return res.status(403).json({ error: "Fullname must be at least 3 letters long." });
    }
    if (!email.length) {
        return res.status(403).json({ error: "Enter a valid email." });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Email is invalid" });
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters." });
    }
    
    bcrypt.hash(password, 10, async (err, hashed_password) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let username = await generateUsername(email);
        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        });
        
        user.save()
            .then((u) => {
                return res.status(200).json(formatDataToSend(u));
            })
            .catch(err => {
                return res.status(500).json({ error: err.message });
            });
    });
});

server.post("/signin", async (req, res) => {
    const { email, password } = req.body;

    User.findOne({ "personal_info.email": email })
        .then((user) => {
            if (!user) {
                return res.status(403).json({ error: "Email not found" });
            }
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(403).json({ error: "Error occurred while login" });
                }
                if (!result) {
                    return res.status(403).json({ error: "Incorrect password" });
                } else {
                    return res.status(200).json(formatDataToSend(user));
                }
            });
        })
        .catch(err => {
            return res.status(403).json({ error: err.message });
        });
});

// Google authentication
server.post("/google-auth", async (req, res) => {
    const { access_token } = req.body;
    try {
        const decodedUser = await getAuth().verifyIdToken(access_token);
        const { email, fullname, picture } = decodedUser;
        const formattedPicture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname username personal_info.profile_img google_auth");

        if (user) {
            if (!user.google_auth) return res.status(403).json({ error: "This email was signed up without Google." });
        } else {
            const username = await generateUsername(email);
            user = new User({ personal_info: { fullname, email, profile_img: formattedPicture, username }, google_auth: true });
            await user.save();
        }

        return res.status(200).json(formatDataToSend(user));
    } catch (err) {
        return res.status(500).json({ error: "Failed to authenticate with Google." });
    }
});

// Blog routes
server.get('/latest-blogs', (req, res) => {
    const maxLimit = 5;
    const page = parseInt(req.query.page) || 1; // Pagination

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => res.status(200).json({ blogs }))
        .catch(err => res.status(500).json({ error: err.message }));
});

server.get("/all-latest-blog-count", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => res.status(200).json({ totalDocs: count }))
        .catch(err => res.status(500).json({ error: err.message }));
});

server.get('/trending-blogs', (req, res) => {
    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 })
        .select("blog_id title publishedAt -_id")
        .limit(5)
        .then(blogs => res.status(200).json({ blogs }))
        .catch(err => res.status(500).json({ error: err.message }));
});

server.post('/search-blogs', (req, res) => {
    const { tag, query, page } = req.body;
    const findQuery = tag ? { tags: tag, draft: false } : (query ? { draft: false, title: new RegExp(query, 'i') } : { draft: false });

    const maxLimit = 2;

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => res.status(200).json({ blogs }))
        .catch(err => res.status(500).json({ error: err.message }));
});

server.post('/search-blog-counts',(req,res)=>{
    let {tag,query} = req.body;
    let findQuery;
    if(tag){
        findQuery = { tags:tag, draft:false };
    }else{
        if(query){
            findQuery ={ draft:false, title: new RegExp(query, 'i')}
        }
    }
    

    Blog.countDocuments(findQuery)
    .then(count=>{
        return res.status(200).json({totalDocs: count})
    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({error:err.message})
    })
})

// Comment routes
// Add comment
server.post("/add-comment", verifyJWT, async (req, res) => {
    const user_id = req.user;
    const { _id: blog_id, comment, blog_author } = req.body;

    if (!comment || comment.length < 1) {
        return res.status(400).json({ error: "Write something to leave a comment" });
    }

    try {
        // Create and save the new comment
        const commentObj = new Comment({ blog_id, blog_author, comment, commented_by: user_id });
        const savedComment = await commentObj.save();

        // Update the blog with the new comment
        await Blog.findOneAndUpdate(
            { _id: blog_id },
            { $push: { comments: savedComment._id }, $inc: { "activity.total_comments": 1 } }
        );

        // Prepare notification object
        const notificationObj = { 
            type: "comment", 
            blog: blog_id, 
            notification_for: blog_author, 
            user: user_id, 
            comment: savedComment._id 
        };

        // Save the notification
        await new Notification(notificationObj).save();

        return res.status(200).json(savedComment);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

server.post("/create-blog", verifyJWT, (req, res) => {
    let authorId = req.user;
    let { title, des, banner, content, draft, tags } = req.body;

    if (!title || title.length === 0) {
        return res.status(403).json({ error: "You must provide a title to publish the blog" });
    }
    if (!des || des.length > 200) {
        return res.status(403).json({ error: "You must provide blog description under 200 characters" });
    }
    if (!banner || banner.length === 0) {
        return res.status(403).json({ error: "You must provide blog banner to publish it" });
    }
    if (!content || content.blocks.length === 0) {
        return res.status(403).json({ error: "There must be some blog content to publish it." });
    }
    if (!tags || tags.length === 0 || tags.length > 10) {
        return res.status(403).json({ error: "Provide tags to publish it" });
    }

    tags = tags.map(tag => tag.toLowerCase());
    let blog_id = title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();
    let blog = new Blog({
        title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
    });

    blog.save().then(blog => {
        let incrementVal = draft ? 0 : 1;
        User.findOneAndUpdate({ _id: authorId }, { $inc: { "account.info.total_posts": incrementVal }, $push: { "blog": blog._id } })
            .then(user => {
                return res.status(200).json({ _id: blog.blog_id });
            })
            .catch(err => {
                return res.status(500).json({ error: "Failed to update total posts number" });
            });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    });
});

server.post("/like-blog", verifyJWT, async (req, res) => {
    const user_id = req.user;
    const { _id, likedByUser } = req.body;
    const incrementVal = !likedByUser ? 1 : -1;

    try {
        const blog = await Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } });
        if (!blog) return res.status(404).json({ error: "Blog not found" });

        if (!likedByUser) {
            const like = new Notification({ type: "like", blog: _id, notification_for: blog.author, user: user_id });
            await like.save();
            return res.status(200).json({ liked_by_user: true });
        } else {
            await Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" });
            return res.status(200).json({ liked_by_user: false });
        }
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

server.post('/get-blog', async (req, res) => {
    const { blog_id } = req.body;

    if (!blog_id) return res.status(400).json({ error: "Blog ID is required" });

    try {
        const blog = await Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": 1 } }, { new: true })
            .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
            .select("title des content banner tags activity publishedAt blog_id");

        if (!blog) return res.status(404).json({ error: "Blog not found" });

        if (blog.author && blog.author.personal_info.username) {
            await User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, { $inc: { "account_info.total_reads": 1 } }, { new: true });
        }

        return res.status(200).json({ blog });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

server.post("/isLiked-by-user", verifyJWT, async (req, res) => {
    const user_id = req.user;
    const { _id } = req.body;

    try {
        const likeExists = await Notification.exists({ user: user_id, blog: _id, type: "like" });
        return res.status(200).json({ liked_by_user: !!likeExists });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// Get blog comments
server.post("/get-blog-comments", (req, res) => {
    const { blog_id, skip } = req.body;
    const maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
        .skip(skip)
        .limit(maxLimit)
        .sort({ 'commentedAt': -1 })
        .then(comments => res.status(200).json(comments))
        .catch(err => res.status(500).json({ error: err.message }));
});




// Error handling middleware
server.use(errorHandler);

// Start server
server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
