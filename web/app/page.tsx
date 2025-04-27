// import Image from "next/image";
// import { NextResponse } from "next/server";
import {useRequest} from "@/app/api/config/route"
// import axios from "axios";

export default async function Home() {

    // const response = await axios.get(`https://jsonplaceholder.typicode.com/todos/1`);
    // console.log(response.data);

    
    try {
      const response = await useRequest.get(`/health`,);
      console.log(response.data); // Response data
    } catch {
      console.error("Request failed:");
    }
    
    // return response;

  return (
    <div >
      Hello
    </div>
  );
}
