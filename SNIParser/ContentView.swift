//
//  ContentView.swift
//  SNIParser
//
//  Created by Vladislav Simovic on 27.12.24..
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Hello, world!")
        }
        .padding()
        .onTapGesture {
            SNIParser.shared.execute()
        }
    }
}

#Preview {
    ContentView()
}
