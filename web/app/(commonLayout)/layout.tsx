import React from 'react'
import type { FC } from 'react'
import type { ICommonLayoutProps } from './_layout-client'
import LayoutClient from './_layout-client'
import GA, { GaType } from '@/app/components/base/ga'

const Layout: FC<ICommonLayoutProps> = ({ children }) => {
  return (
    <>
      <GA gaType={GaType.admin} />
      <LayoutClient children={children}></LayoutClient>
    </>
  )
}

export const metadata = {
  title: 'AI.89757',
}

export default Layout
