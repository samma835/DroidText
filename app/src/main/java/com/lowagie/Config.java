package com.lowagie;

import android.content.Context;

/**
 * Created by FcoPardo on 11/9/15.
 */
public class Config {

    private static Context libraryContext;

    public static void setLibraryContext(Context context){
        libraryContext = context;
    }

    public static Context getLibraryContext(){
        return libraryContext.getApplicationContext();
    }


}
