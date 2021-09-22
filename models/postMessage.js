import mongoose from 'mongoose';
const PostSchema = mongoose.Schema({
    title:String,
    message:String,
    name:String,
    creator:String,
    tags:[String],
    selectedFiles:String,
    likes:{
        type:[String],
        default:[]
    },
    unlikes:{
        type:[String],
        default:[]
    },
    comments: { type: [String], default: [] },
    createdAt:{
        type:Date,
        default:new Date()
    },
});

const PostMessage = mongoose.model('PostMessage',PostSchema);
export default PostMessage;